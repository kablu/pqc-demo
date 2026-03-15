package com.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * =========================================================================
 * Task 04 — Issue X.509 Certificate from CSR (CA signs Subscriber Cert)
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * CA (RA ki taraf se) subscriber ka CSR process karta hai aur X.509v3
 * certificate issue karta hai. Yeh RA system ka PRIMARY function hai —
 * har approved CSR ke liye RA yahi karta hai.
 * </p>
 *
 * <h2>CA ke Perspective Se Kya Hota Hai?</h2>
 * <ol>
 *   <li>CSR receive karo (Task03 se)</li>
 *   <li>CSR ka signature verify karo (proof of possession)</li>
 *   <li>Subscriber identity verify karo (RA ka kaam — LDAP, database check)</li>
 *   <li>Certificate profile select karo (TLS, S/MIME, Code Signing)</li>
 *   <li>Certificate build karo: CSR ki public key + CA policy + validity</li>
 *   <li>CA private key se sign karo → issued certificate</li>
 *   <li>Certificate subscriber ko deliver karo + audit log mein record karo</li>
 * </ol>
 *
 * <h2>Issued Cert vs CSR — Kya Farq Hai?</h2>
 * <pre>
 * CSR                          Issued Certificate
 * ─────────────────            ──────────────────────────────────────
 * Requestor signs it           CA signs it
 * No serial number             Has serial (unique at this CA)
 * No validity period           Has notBefore, notAfter
 * Subject only                 Subject + Issuer (CA's DN)
 * Requested extensions         CA-enforced extensions (policy applied)
 * Not trusted anywhere         Trusted by anyone who trusts the CA
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task04_IssueCertFromCsr</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class Task04_IssueCertFromCsr {

    /**
     * TLS server certificate validity in days.
     *
     * <p>WHY 397 days (≈13 months)?<br>
     * Apple Safari (since 2020), Chrome, and Firefox enforce max 398-day
     * TLS cert validity. Certs longer than this are rejected by browsers.
     * For RA systems, we use 397 as a safe margin below the 398-day limit.</p>
     */
    private static final int TLS_CERT_VALIDITY_DAYS = 397;

    /**
     * Entry point — issues a certificate from the CSR generated in Task03.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if certificate issuance fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 04 — Issue Certificate from CSR");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // Ensure prerequisite tasks have run
        if (CertificateStore.caKeyPair == null) {
            Task02_SelfSignedCaCertificate.main(new String[]{});
        }
        if (CertificateStore.entityKeyPair == null) {
            Task03_CsrGeneration.main(new String[]{});
        }

        // Build a fresh CSR (simulating a real CSR from subscriber)
        PKCS10CertificationRequest csr = Task03_CsrGeneration.buildCsr(
            CertificateStore.entityKeyPair,
            "device-001.company.com"
        );

        // Step 1: Validate CSR before processing (RA's job)
        validateCsr(csr);

        // Step 2: Issue certificate from CSR using CA key
        X509Certificate issuedCert = issueCertificate(csr);

        // Step 3: Verify the issued cert's signature against CA cert
        verifyIssuedCert(issuedCert, CertificateStore.caCert);

        // Step 4: Print issued certificate details
        Task02_SelfSignedCaCertificate.printCertificateDetails(issuedCert);

        // Store for Tasks 05–08
        CertificateStore.entityCert = issuedCert;

        System.out.println("✅ Task 04 Complete — Certificate issued successfully!");
        System.out.println("   Next Step → Task05_CrlGeneration.java");
    }

    // =========================================================================
    // Step 1 — Validate the CSR (RA Validation Layer)
    // =========================================================================

    /**
     * Validates a PKCS#10 CSR before the CA processes it.
     *
     * <p><b>WHY validate before issuing?</b><br>
     * RA (Registration Authority) ki PRIMARY responsibility yahi hai — validate
     * karna before forwarding to CA. Without this, malicious CSRs could cause:
     * <ul>
     *   <li>Invalid certificates (wrong key, wrong identity)</li>
     *   <li>Policy violations (wrong key size, prohibited extensions)</li>
     *   <li>Key compromise (if requestor doesn't own the private key)</li>
     * </ul>
     * </p>
     *
     * @param csr the PKCS#10 CSR to validate
     * @throws Exception if CSR signature is invalid or policy check fails
     */
    public static void validateCsr(PKCS10CertificationRequest csr) throws Exception {
        System.out.println("🔍 RA Validation Step — Checking CSR...");

        // Check 1: Verify proof of possession (CSR self-signature)
        // This is MANDATORY — if this fails, reject immediately
        org.bouncycastle.operator.ContentVerifierProvider verifier =
            new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(csr.getSubjectPublicKeyInfo());

        if (!csr.isSignatureValid(verifier)) {
            throw new SecurityException("CSR signature INVALID — Proof of Possession failed! Rejecting CSR.");
        }
        System.out.println("   ✔ CSR signature valid (Proof of Possession confirmed)");

        // Check 2: Key size policy — minimum RSA-2048 required
        // Convert SubjectPublicKeyInfo to Java PublicKey for RSA modulus check
        java.security.PublicKey publicKey = org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
            .class.getConstructor().newInstance()
            .setProvider("BC")
            .getPublicKey(csr.getSubjectPublicKeyInfo());

        if (publicKey instanceof java.security.interfaces.RSAPublicKey rsaPk) {
            int keyBits = rsaPk.getModulus().bitLength();
            if (keyBits < 2048) {
                throw new SecurityException("Key size " + keyBits + " bits is below minimum 2048-bit policy!");
            }
            System.out.println("   ✔ Key size " + keyBits + " bits meets minimum policy (2048+)");
        }

        // Check 3: Subject DN must not be empty
        if (csr.getSubject().toString().isBlank()) {
            throw new SecurityException("CSR Subject DN is empty — cannot issue certificate!");
        }
        System.out.println("   ✔ Subject DN present: " + csr.getSubject());

        System.out.println("   ✔ All RA validation checks passed!\n");
    }

    // =========================================================================
    // Step 2 — Issue the Certificate
    // =========================================================================

    /**
     * Issues an X.509v3 TLS server certificate from a validated CSR.
     *
     * <p><b>Key steps explained:</b>
     * <ol>
     *   <li>Extract public key from CSR — goes into the issued cert</li>
     *   <li>Extract requested extensions from CSR extensionRequest attribute</li>
     *   <li>Build cert with CA as issuer, CSR subject as subject</li>
     *   <li>Apply CA policy: set validity, serial, mandatory extensions</li>
     *   <li>Sign with CA private key — this binds identity to public key</li>
     * </ol>
     * </p>
     *
     * <p><b>SubjectKeyIdentifier WHY?</b><br>
     * SKI = SHA-1 hash of the public key. Used by clients to match cert to
     * cached public keys. Required by RFC 5280 §4.2.1.2 for CA certs and
     * recommended for end-entity certs.</p>
     *
     * <p><b>AuthorityKeyIdentifier WHY?</b><br>
     * AKI = identifies which CA key signed this cert. Crucial for:
     * (1) Chain building — clients use AKI to find the issuing CA cert
     * (2) Key rollover — same CA DN, multiple keys; AKI disambiguates</p>
     *
     * @param csr the validated PKCS#10 CSR from subscriber
     * @return the signed {@link X509Certificate}
     * @throws Exception if certificate construction or signing fails
     */
    public static X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws Exception {
        System.out.println("🏭 Issuing Certificate from CSR...");

        // ---- Extract subject and public key from CSR ----
        // getSubject() = subscriber's DN — they get exactly what they requested
        // (RA may modify DN based on policy — e.g., enforce org name from LDAP)
        X500Name subjectDn = csr.getSubject();

        // Convert CSR's SubjectPublicKeyInfo to Java PublicKey
        // This is the subscriber's public key — goes into the issued certificate
        java.security.PublicKey subjectPublicKey =
            new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                .setProvider("BC")
                .getPublicKey(csr.getSubjectPublicKeyInfo());

        // ---- Issuer DN = CA's subject DN ----
        // WHY? The issued cert's issuer must match the CA cert's subject exactly.
        // This is how trust chain works: cert.issuer == caCert.subject
        X500Name issuerDn = new X500Name(
            CertificateStore.caCert.getSubjectX500Principal().getName()
        );

        // ---- Validity Period ----
        Instant now      = Instant.now();
        Date    notBefore = Date.from(now);
        Date    notAfter  = Date.from(now.plus(TLS_CERT_VALIDITY_DAYS, ChronoUnit.DAYS));

        // ---- Serial Number — MUST be unique per CA ----
        // WHY random? RFC 5280 §4.1.2.2: serial must be unique within a CA.
        // Random 64-bit serial prevents prediction and collision at scale.
        BigInteger serial = Task03_CsrGeneration.generateSecureSerial();

        // ---- Build Certificate ----
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuerDn,           // issuer = CA's DN
            serial,             // unique random serial
            notBefore,          // validity start = now
            notAfter,           // validity end = now + 397 days
            subjectDn,          // subject = from CSR
            subjectPublicKey    // subscriber's public key from CSR
        );

        // ---- Extension Utilities ----
        // JcaX509ExtensionUtils provides helper methods to compute SKI/AKI
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // Extension 1: SubjectKeyIdentifier
        // SHA-1 fingerprint of the subjectPublicKey — identifies this key in key stores
        certBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,  // NOT critical — informational
            extUtils.createSubjectKeyIdentifier(subjectPublicKey)
        );

        // Extension 2: AuthorityKeyIdentifier
        // Links this cert back to the CA cert that signed it
        // createAuthorityKeyIdentifier(caCert) extracts CA cert's SKI
        certBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,  // NOT critical — used for chain building, not enforcement
            extUtils.createAuthorityKeyIdentifier(CertificateStore.caCert)
        );

        // Extension 3: BasicConstraints — NOT a CA cert
        // isCA = false for end-entity certs. This prevents cert misuse as a CA.
        // CRITICAL = true: if verifier doesn't understand, reject cert.
        certBuilder.addExtension(
            Extension.basicConstraints,
            true,
            new org.bouncycastle.asn1.x509.BasicConstraints(false) // isCA = false
        );

        // Extension 4: KeyUsage — TLS server cert profile
        certBuilder.addExtension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );

        // Extension 5: Copy SANs from CSR extensionRequest (if present)
        // WHY copy SANs? The CSR requested specific SANs (Task03). If policy
        // allows it, we MUST include them in the issued cert for TLS to work.
        Extensions csrExtensions = extractExtensionsFromCsr(csr);
        if (csrExtensions != null) {
            Extension san = csrExtensions.getExtension(Extension.subjectAlternativeName);
            if (san != null) {
                certBuilder.addExtension(san);
                System.out.println("   ✔ SAN extension copied from CSR to issued cert");
            }
        }

        // ---- Sign with CA Private Key ----
        // SHA384withRSA = SHA-384 hash + RSA PKCS#1 v1.5 signature
        // WHY SHA-384 for issued cert? NIST recommends >= SHA-256 for new certs.
        // SHA-384 provides 192-bit security, matching RSA-4096 key strength.
        ContentSigner caSigner = new JcaContentSignerBuilder("SHA384withRSA")
            .setProvider("BC")
            .build(CertificateStore.caKeyPair.getPrivate()); // CA private key signs

        X509CertificateHolder certHolder = certBuilder.build(caSigner);

        // Convert BC CertificateHolder → Java X509Certificate
        X509Certificate issuedCert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);

        System.out.printf("✔ Certificate issued! Serial: %s%n%n", issuedCert.getSerialNumber().toString(16));
        return issuedCert;
    }

    // =========================================================================
    // Step 3 — Verify Issued Certificate Against CA
    // =========================================================================

    /**
     * Verifies the issued certificate's signature using the CA's public key.
     *
     * <p><b>WHY verify after issuing?</b><br>
     * After signing, verify confirms: the CA private key correctly signed the cert,
     * and the CA public key can verify it. This is the same verification every
     * TLS client performs during certificate chain validation. If this fails,
     * something is seriously wrong with the CA or cert assembly.</p>
     *
     * <p><b>In TLS chain validation:</b>
     * <pre>
     * end-entity cert → verify signature with intermediate CA's public key
     * intermediate cert → verify signature with root CA's public key
     * root cert → self-signed → in trusted trust store
     * </pre>
     * </p>
     *
     * @param issuedCert the certificate to verify
     * @param caCert     the CA certificate (issuer's cert) containing the verifying public key
     * @throws Exception if signature verification fails
     */
    public static void verifyIssuedCert(X509Certificate issuedCert,
                                         X509Certificate caCert) throws Exception {
        System.out.println("🔍 Verifying issued certificate against CA...");

        try {
            // verify(PublicKey) — checks signature of issuedCert using caCert's public key
            // If issuedCert.issuer == caCert.subject AND signature is valid → cert is genuine
            issuedCert.verify(caCert.getPublicKey(), java.security.Security.getProvider("BC"));

            System.out.println("   ✅ Certificate signature VALID — CA correctly signed this cert!");
            System.out.println("   Issuer   : " + issuedCert.getIssuerX500Principal().getName());
            System.out.println("   Subject  : " + issuedCert.getSubjectX500Principal().getName());
            System.out.println("   Serial   : " + issuedCert.getSerialNumber().toString(16));
        } catch (Exception e) {
            System.out.println("   ❌ Certificate verification FAILED: " + e.getMessage());
            throw e;
        }
        System.out.println();
    }

    // =========================================================================
    // Helper — Extract Extensions from CSR
    // =========================================================================

    /**
     * Extracts the Extensions block from a PKCS#10 CSR's extensionRequest attribute.
     *
     * <p><b>WHY extract?</b><br>
     * CSR extensions are buried inside a PKCS#9 {@code extensionRequest} attribute
     * (OID 1.2.840.113549.1.9.14). To copy SANs to the issued cert, we must
     * navigate this structure: CSR → attributes → extensionRequest → Extensions.</p>
     *
     * @param csr the PKCS#10 CSR containing extension requests
     * @return the {@link Extensions} block, or {@code null} if no extensions requested
     */
    private static Extensions extractExtensionsFromCsr(PKCS10CertificationRequest csr) {
        // getAttributes(OID) returns attributes matching the given OID
        // PKCSObjectIdentifiers.pkcs_9_at_extensionRequest = 1.2.840.113549.1.9.14
        org.bouncycastle.asn1.pkcs.Attribute[] attributes =
            csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

        if (attributes == null || attributes.length == 0) {
            return null; // No extension request in CSR
        }

        // First attribute, first value = the Extensions ASN.1 sequence
        // getAttrValues().getObjectAt(0) navigates the ASN.1 structure
        return Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
    }
}
