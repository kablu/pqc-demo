package com.pqc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * =========================================================================
 * Task 03 — CSR (Certificate Signing Request) Generation — PKCS#10
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * CSR (Certificate Signing Request) generate karna seekhenge. CSR ek message
 * hai jo subscriber CA ko bhejta hai — "Mujhe certificate chahiye, mere paas
 * yeh public key hai, yeh meri identity hai." CA CSR verify karta hai aur
 * certificate issue karta hai (Task04). Yeh RA system ka CORE workflow hai.
 * </p>
 *
 * <h2>CSR Kyun Zaroori Hai?</h2>
 * <p>
 * CA ko kabhi subscriber ki private key nahi milti — that would be insecure.
 * CSR mein sirf PUBLIC KEY hoti hai. Subscriber private key se CSR sign karta
 * hai — isse "Proof of Possession" kehte hain. CA verify karta hai ki CSR mein
 * public key ki corresponding private key requestor ke paas hai.
 * </p>
 *
 * <h2>CSR = PKCS#10 Structure (RFC 2986)</h2>
 * <pre>
 * CertificationRequest {
 *   CertificationRequestInfo {
 *     version        = 0
 *     subject        = X500Name (requestor's DN)
 *     subjectPKInfo  = SubjectPublicKeyInfo (public key)
 *     attributes     = ExtensionRequest (SANs, KeyUsage, etc.)
 *   }
 *   signatureAlgorithm = SHA256withRSA
 *   signature          = [signed with requestor's private key]
 * }
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task03_CsrGeneration</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 * @see     Task04_IssueCertFromCsr — uses this CSR to issue a certificate
 */
public class Task03_CsrGeneration {

    /**
     * Entry point — generates an RSA key pair and creates a PKCS#10 CSR.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if key generation or CSR creation fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 03 — CSR (PKCS#10) Generation");
        System.out.println("=============================================================\n");

        // Always register BC provider first
        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // Ensure CA cert exists (needed for context, not for CSR itself)
        if (CertificateStore.caKeyPair == null) {
            Task02_SelfSignedCaCertificate.main(new String[]{});
        }

        // Step 1: Generate subscriber (end-entity) key pair
        // WHY separate key pair? Subscriber ke paas alag keypair hota hai.
        // CA ka keypair alag — trust hierarchy maintain hoti hai.
        System.out.println("🔑 Generating End-Entity (Subscriber) RSA-4096 Key Pair...");
        KeyPair entityKeyPair = Task01_RsaKeyPairGeneration.generateRsaKeyPair();
        CertificateStore.entityKeyPair = entityKeyPair;

        // Step 2: Build the CSR
        PKCS10CertificationRequest csr = buildCsr(entityKeyPair, "device-001.company.com");

        // Step 3: Print CSR details
        printCsrDetails(csr);

        // Step 4: Export CSR as PEM (this is what you send to RA/CA)
        printCsrPem(csr);

        // Step 5: Verify CSR's self-signature (proof of possession)
        verifyCsrSignature(csr);

        // Store for Task04
        CertificateStore.entityKeyPair = entityKeyPair;

        System.out.println("\n✅ Task 03 Complete — CSR generated and verified!");
        System.out.println("   Next Step → Task04_IssueCertFromCsr.java");
    }

    // =========================================================================
    // Step 1 — Build the CSR with Extensions
    // =========================================================================

    /**
     * Builds a PKCS#10 CSR for a TLS server certificate with Subject Alternative Names.
     *
     * <p><b>WHY JcaPKCS10CertificationRequestBuilder?</b><br>
     * BouncyCastle's JCA-friendly builder that accepts standard Java types
     * ({@link java.security.PublicKey}) and produces a PKCS#10 CSR. The underlying
     * {@code PKCS10CertificationRequestBuilder} works with raw ASN.1 but
     * the Jca wrapper is more convenient for Java developers.</p>
     *
     * <p><b>Extensions in CSR:</b><br>
     * RFC 2985 defines the "extensionRequest" attribute (OID 1.2.840.113549.1.9.14)
     * that allows a CSR to REQUEST specific extensions to be included in the
     * issued certificate. The CA MAY honour or ignore these requests based on
     * certificate profile policy.</p>
     *
     * <p><b>WHY SubjectAlternativeName (SAN)?</b><br>
     * Modern TLS (RFC 2818) requires servers to use SANs, not just CN, to
     * identify hostnames. Browsers ignore CN for hostname validation — SAN is
     * MANDATORY. Our RA must carry SAN from CSR to issued cert.</p>
     *
     * @param entityKeyPair the subscriber's key pair (private key signs CSR, public key goes in CSR)
     * @param commonName    the primary DNS name for this certificate
     * @return the PKCS#10 {@link PKCS10CertificationRequest}
     * @throws Exception if extension generation or signing fails
     */
    public static PKCS10CertificationRequest buildCsr(KeyPair entityKeyPair,
                                                       String commonName) throws Exception {
        System.out.println("📝 Building CSR for: " + commonName);

        // ---- Subject DN ----
        // CN = the primary common name. For TLS certs, this is often the hostname.
        // O, C = organizational identity for the subscriber.
        // WHY O and C? Organizational validation (OV) certs require verified
        // org details. Extended Validation (EV) requires even more attributes.
        X500Name subjectDn = new X500Name(
            "CN=" + commonName + "," +
            "O=PQC Demo Organization," +
            "C=IN"
        );

        // ---- Create the CSR Builder ----
        // Parameters: (subjectDN, publicKey)
        // WHY publicKey and not keyPair? CSR contains ONLY the public key.
        // The private key is used only for signing the CSR — it never leaves the subscriber.
        JcaPKCS10CertificationRequestBuilder csrBuilder =
            new JcaPKCS10CertificationRequestBuilder(subjectDn, entityKeyPair.getPublic());

        // ---- Build Extension Request Attribute ----
        // RFC 2985: extensionRequest is a PKCS#9 attribute containing requested extensions.
        // CA reads this, applies policy, and may include these in the issued cert.
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        // Extension 1: SubjectAlternativeName (SAN) — MANDATORY for TLS certs
        // GeneralName.dNSName = DNS hostname type (vs IP address, email, URI)
        // WHY multiple SANs? Single cert can cover multiple hostnames (SAN list).
        GeneralNames subjectAltNames = new GeneralNames(new GeneralName[]{
            new GeneralName(GeneralName.dNSName, commonName),              // primary hostname
            new GeneralName(GeneralName.dNSName, "*.company.com"),        // wildcard subdomain
            new GeneralName(GeneralName.iPAddress,                        // numeric IP SAN
                new DEROctetString(new byte[]{10, 0, 0, 1}))             // 10.0.0.1
        });

        // addExtension(OID, critical, value)
        // SAN is NOT critical by default — browsers still validate it
        // (RFC 5280: critical means "if you don't understand this, reject the cert")
        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        // Extension 2: KeyUsage — restrict what this cert can be used for
        // For TLS server: digitalSignature (TLS handshake) + keyEncipherment (RSA key exchange)
        // WHY not keyCertSign? Only CA certs need that — end-entity certs must NOT have it
        extGen.addExtension(
            Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );

        // Add the extensions as a PKCS#9 extensionRequest attribute to the CSR
        // PKCSObjectIdentifiers.pkcs_9_at_extensionRequest = OID 1.2.840.113549.1.9.14
        csrBuilder.addAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
            extGen.generate()  // generates the Extensions ASN.1 structure
        );

        // ---- Sign the CSR ----
        // ContentSigner: algorithm + private key used to sign the CSR
        // WHY sign with SHA256withRSA (not SHA384)? CSRs are temporary — they're just
        // used to prove possession. The ISSUED cert will use SHA-384 (stronger).
        // SHA-256 is acceptable and widely supported by all CAs including EJBCA.
        ContentSigner csrSigner = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(entityKeyPair.getPrivate());  // subscriber's private key signs the CSR

        // build(contentSigner) = assembles CertificationRequestInfo and computes signature
        PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

        System.out.println("✔ CSR built and signed by entity private key\n");
        return csr;
    }

    // =========================================================================
    // Step 2 — Print CSR Details
    // =========================================================================

    /**
     * Prints the decoded contents of a PKCS#10 CSR.
     *
     * <p><b>WHY inspect CSR?</b><br>
     * RA operator must validate the CSR before sending to CA. Checks include:
     * subject DN matches registered entity, key size meets policy, SANs are
     * authorized, no suspicious extensions. This is the RA's core validation role.</p>
     *
     * @param csr the PKCS#10 CSR to inspect
     * @throws Exception if attribute parsing fails
     */
    public static void printCsrDetails(PKCS10CertificationRequest csr) throws Exception {
        System.out.println("📋 CSR Details:");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");

        // getSubject() — the DN the requestor wants on their certificate
        System.out.println("   │ Subject         : " + csr.getSubject());

        // getSignatureAlgorithm() — how the CSR was signed (proof-of-possession algo)
        System.out.println("   │ Signature Algo  : " + csr.getSignatureAlgorithm().getAlgorithm());

        // Public key info — this is the key that will appear in the issued cert
        System.out.printf( "   │ Public Key Size : %d bytes (encoded)%n",
            csr.getSubjectPublicKeyInfo().getEncoded().length);

        // getAttributes() — PKCS#9 attributes including extensionRequest
        System.out.println("   │ Attributes Count: " + csr.getAttributes().length);

        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 3 — PEM Export (What You Send to RA/CA)
    // =========================================================================

    /**
     * Exports the CSR in PEM format — the standard interchange format.
     *
     * <p><b>WHY PEM for CSR?</b><br>
     * CSRs are sent from subscriber to RA via: web portal upload, EST protocol
     * (Task13), SCEP, or email. All these channels expect PEM format.
     * {@code openssl req -verify -in request.csr -text} can parse this output.</p>
     *
     * <p><b>Verify with openssl:</b><br>
     * {@code openssl req -text -noout -verify -in request.pem}</p>
     *
     * @param csr the PKCS#10 CSR to export
     * @throws Exception if DER encoding fails
     */
    public static void printCsrPem(PKCS10CertificationRequest csr) throws Exception {
        // getEncoded() returns DER (binary ASN.1) bytes
        byte[] derBytes = csr.getEncoded();

        // Wrap DER bytes in PEM format (Base64 with 64-char line breaks)
        String pem = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(derBytes)
            + "\n-----END CERTIFICATE REQUEST-----";

        System.out.println("📄 CSR in PEM Format (send this to RA/CA):");
        System.out.println(pem);
        System.out.printf("%n   CSR DER size: %d bytes%n%n", derBytes.length);
    }

    // =========================================================================
    // Step 4 — Verify CSR Self-Signature (Proof of Possession)
    // =========================================================================

    /**
     * Verifies the CSR's self-signature to confirm proof of possession.
     *
     * <p><b>WHY verify CSR signature?</b><br>
     * The CSR contains a public key AND is signed by the corresponding private key.
     * Verifying the signature proves the requestor POSSESSES the private key
     * for the public key in the CSR. This is "Proof of Possession" (PoP) —
     * mandated by RFC 4211 and PKIX standards.</p>
     *
     * <p><b>RA responsibility:</b><br>
     * The RA MUST verify CSR signature before forwarding to CA. A CSR with
     * invalid signature could indicate: tampering, key mismatch, or attack.
     * EJBCA and other CAs also verify this, but RA is the first gate.</p>
     *
     * @param csr the PKCS#10 CSR to verify
     * @throws Exception if signature verification fails
     */
    public static void verifyCsrSignature(PKCS10CertificationRequest csr) throws Exception {
        System.out.println("🔍 Verifying CSR Proof of Possession (self-signature)...");

        // ContentVerifierProvider: creates a verifier for the CSR's signature algorithm
        // JcaContentVerifierProviderBuilder bridges BC and JCA signature verification
        org.bouncycastle.operator.ContentVerifierProvider verifierProvider =
            new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                // getSubjectPublicKeyInfo() = public key from inside the CSR
                // We verify using the PUBLIC KEY declared IN the CSR itself
                .build(csr.getSubjectPublicKeyInfo());

        // isSignatureValid() — returns true if signature matches the public key
        // This is Proof of Possession: private key holder created this CSR
        boolean isValid = csr.isSignatureValid(verifierProvider);

        if (isValid) {
            System.out.println("   ✅ CSR Signature VALID — Proof of Possession confirmed!");
            System.out.println("   The requestor holds the private key for the public key in this CSR.");
        } else {
            System.out.println("   ❌ CSR Signature INVALID — reject this CSR!");
        }
        System.out.println();
    }

    /**
     * Utility method — generates a cryptographically secure random serial number.
     *
     * <p><b>WHY random serial?</b><br>
     * RFC 5280 §4.1.2.2 requires serial numbers to be unique per CA and
     * MUST be a positive integer. Using a 64-bit random value avoids serial
     * prediction attacks and collisions even at high issuance volume.
     * Never use sequential integers in production — predictable serials
     * enable certificate harvesting attacks.</p>
     *
     * @return a positive 64-bit random {@link BigInteger} suitable for cert serial
     */
    public static BigInteger generateSecureSerial() {
        // new BigInteger(64, random): generates a random 64-bit positive integer
        // 64 bits = sufficient entropy for serial uniqueness per CA
        // SecureRandom: cryptographically strong random source
        return new BigInteger(64, new SecureRandom());
    }
}
