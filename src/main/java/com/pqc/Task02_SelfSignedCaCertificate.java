package com.pqc;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * =========================================================================
 * Task 02 — Self-Signed CA Certificate Creation using BouncyCastle
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * CA (Certificate Authority) certificate banate hain — yeh PKI trust chain
 * ka ROOT hai. CA cert self-signed hota hai kyunki koi upar wala CA nahi hota.
 * Is CA cert ka use baad mein Tasks 03-05 mein karenge subscriber certs issue
 * karne ke liye aur CRL sign karne ke liye.
 * </p>
 *
 * <h2>Self-Signed Matlab?</h2>
 * <p>
 * Normal cert: Subject != Issuer — kisi aur CA ne sign kiya.
 * Self-signed: Subject == Issuer — khud ne khud ko sign kiya.
 * Root CA ki koi aur sign nahi karta — isliye self-signed trusted hota hai
 * jab explicitly "Trust Store" mein add karo.
 * </p>
 *
 * <h2>X.509 Certificate Structure (Simplified)</h2>
 * <pre>
 * X.509v3 Certificate
 *   ├── Version        : v3 (3) — mandatory for extensions
 *   ├── SerialNumber   : unique integer — identifies cert at issuing CA
 *   ├── Issuer         : DN of who signed this cert (CA's Subject)
 *   ├── Validity       : NotBefore + NotAfter dates
 *   ├── Subject        : DN of the cert owner
 *   ├── PublicKeyInfo  : owner's public key + algorithm
 *   └── Extensions
 *       ├── BasicConstraints  : isCA=true, pathLenConstraint
 *       ├── KeyUsage          : keyCertSign, cRLSign (CA-specific)
 *       └── SubjectKeyIdentifier
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task02_SelfSignedCaCertificate</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 * @see     Task03_CsrGeneration — uses this CA to issue certs
 */
public class Task02_SelfSignedCaCertificate {

    /**
     * CA validity in years.
     *
     * <p>WHY 10 years? CA certificates live longer than end-entity certs.
     * Root CA: 20-25 years. Sub CA: 10 years. End-entity: 1-3 years.
     * CA must outlive ALL certificates it issues.</p>
     */
    private static final int CA_VALIDITY_YEARS = 10;

    /**
     * Certificate serial number for the CA cert.
     *
     * <p>WHY BigInteger.ONE? Serial numbers uniquely identify certificates
     * within an issuing CA. For a self-signed root CA, serial 1 is conventional.
     * For issued certs, use a secure random BigInteger to prevent serial prediction
     * attacks (RFC 5280 §4.1.2.2 requires serial to be unique per CA).</p>
     */
    private static final BigInteger CA_SERIAL = BigInteger.ONE;

    /**
     * Entry point — creates a self-signed CA certificate.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if key generation or certificate creation fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 02 — Self-Signed CA Certificate Creation");
        System.out.println("=============================================================\n");

        // Register BouncyCastle — always first step (reuse from Task01)
        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // Step 1: Generate RSA-4096 key pair for the CA
        KeyPair caKeyPair = Task01_RsaKeyPairGeneration.generateRsaKeyPair();

        // Step 2: Build and sign the self-signed CA certificate
        X509Certificate caCert = buildSelfSignedCaCert(caKeyPair);

        // Step 3: Print and verify the certificate
        printCertificateDetails(caCert);

        verifyCertSignature(caCert);

        // Step 4: Store for use in subsequent tasks
        CertificateStore.caKeyPair = caKeyPair;
        CertificateStore.caCert    = caCert;

        System.out.println("\n✅ Task 02 Complete — Self-Signed CA Certificate created!");
        System.out.println("   Next Step → Task03_CsrGeneration.java");
    }

    // =========================================================================
    // Step 1 — Define CA Identity (Distinguished Name)
    // =========================================================================

    /**
     * Creates the Distinguished Name (DN) for the CA.
     *
     * <p><b>WHY X500Name?</b><br>
     * X.500 Distinguished Name is the standard way to identify certificate
     * subjects and issuers in X.509. It's a hierarchical name with typed
     * attributes. RFC 4514 defines the string format.</p>
     *
     * <p><b>DN attributes:</b>
     * <ul>
     *   <li>{@code CN} = Common Name — human-readable identifier of the entity</li>
     *   <li>{@code O}  = Organization — company or unit name</li>
     *   <li>{@code OU} = Organizational Unit — department</li>
     *   <li>{@code C}  = Country — 2-letter ISO 3166 code</li>
     *   <li>{@code ST} = State/Province</li>
     *   <li>{@code L}  = Locality/City</li>
     * </ul>
     * </p>
     *
     * <p><b>WHY order matters:</b> RFC 4514 specifies attributes in reverse order.
     * Most PKI tools use C → ST → L → O → OU → CN order (most general to specific).</p>
     *
     * @return the CA's X500Name (Distinguished Name)
     */
    public static X500Name buildCaDn() {
        // X500Name string format: attribute=value pairs separated by commas.
        // BouncyCastle parses this RFC 4514 format directly.
        return new X500Name(
            "CN=PQC-RA Root CA," +
            "OU=PKI Team," +
            "O=PQC Demo Organization," +
            "C=IN"
        );
    }

    // =========================================================================
    // Step 2 — Build the Self-Signed CA Certificate
    // =========================================================================

    /**
     * Builds and signs a self-signed X.509v3 CA certificate.
     *
     * <p><b>WHY JcaX509v3CertificateBuilder?</b><br>
     * BouncyCastle's JCA-bridging class that wraps {@link X509v3CertificateBuilder}
     * with convenient Java type inputs (Date, KeyPair, BigInteger instead of
     * raw ASN.1 types). Produces an X.509v3 certificate with extensions.</p>
     *
     * <p><b>Certificate building process:</b>
     * <ol>
     *   <li>Create builder with mandatory fields (issuer, serial, validity, subject, pubKey)</li>
     *   <li>Add X.509v3 extensions (BasicConstraints, KeyUsage, SubjectKeyIdentifier)</li>
     *   <li>Build a {@link X509CertificateHolder} (unsigned certificate structure)</li>
     *   <li>Sign it with the CA private key using {@link ContentSigner}</li>
     *   <li>Convert to JCA {@link X509Certificate} for use with Java APIs</li>
     * </ol>
     * </p>
     *
     * @param caKeyPair the CA's RSA key pair (public goes in cert, private signs it)
     * @return signed {@link X509Certificate} for the CA
     * @throws Exception if certificate building or signing fails
     */
    public static X509Certificate buildSelfSignedCaCert(KeyPair caKeyPair) throws Exception {

        System.out.println("📜 Building Self-Signed CA Certificate...");

        // ---- Define Subject & Issuer DN ----
        // For self-signed cert: subject == issuer (same entity signs itself)
        X500Name caDn = buildCaDn();
        System.out.println("   Subject/Issuer DN : " + caDn);

        // ---- Define Validity Period ----
        // notBefore = now (current UTC time — certificates must not be valid before now)
        // notAfter  = now + 10 years (CA cert lives longer than issued certs)
        Instant now      = Instant.now();
        Date    notBefore = Date.from(now);
        Date    notAfter  = Date.from(now.plus(CA_VALIDITY_YEARS * 365L, ChronoUnit.DAYS));
        System.out.printf("   Validity          : %s → %s%n", notBefore, notAfter);

        // ---- Create Certificate Builder ----
        // JcaX509v3CertificateBuilder parameters:
        // (issuerDN, serialNumber, notBefore, notAfter, subjectDN, subjectPublicKey)
        // For self-signed: issuerDN == subjectDN
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            caDn,                        // issuer = self (self-signed)
            CA_SERIAL,                   // serial = 1 for root CA
            notBefore,                   // validity start
            notAfter,                    // validity end
            caDn,                        // subject = self (self-signed)
            caKeyPair.getPublic()        // CA's public key goes into the cert
        );

        // ---- Extension 1: BasicConstraints — CRITICAL ----
        // WHY? BasicConstraints marks this as a CA certificate (isCA=true).
        // Without this extension, browsers/verifiers reject the cert as a CA.
        // pathLenConstraint = 0 means this CA cannot issue INTERMEDIATE CAs —
        // it can only issue END-ENTITY certificates. Use -1 or omit for unlimited depth.
        // CRITICAL = true means: if verifier doesn't understand this extension, reject cert.
        certBuilder.addExtension(
            Extension.basicConstraints,  // OID: 2.5.29.19
            true,                        // critical = true (MUST be critical for CA certs per RFC 5280)
            new BasicConstraints(0)      // isCA=true, pathLen=0
        );

        // ---- Extension 2: Key Usage — CRITICAL ----
        // WHY? Restricts what the CA key can be used for.
        // keyCertSign: CA can sign other certificates (core CA function)
        // cRLSign    : CA can sign Certificate Revocation Lists (needed for Task05)
        // digitalSignature: CA can create digital signatures (for OCSP signing)
        // Without KeyUsage extension, any key can be used for anything — bad practice.
        certBuilder.addExtension(
            Extension.keyUsage,          // OID: 2.5.29.15
            true,                        // critical = true (required per RFC 5280 §4.2.1.3)
            new KeyUsage(
                KeyUsage.keyCertSign |   // bit 5: sign certificates
                KeyUsage.cRLSign        // bit 6: sign CRLs
            )
        );

        // ---- Sign the Certificate ----
        // ContentSigner encapsulates the signing algorithm + private key.
        // "SHA384withRSA": SHA-384 digest + RSA signature
        // WHY SHA-384? NIST recommends SHA-384 or SHA-512 for CA certs (2030+ secure).
        // SHA-256 is acceptable for end-entity certs but CA certs deserve stronger hash.
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA384withRSA")
            .setProvider("BC")           // explicitly use BouncyCastle provider
            .build(caKeyPair.getPrivate()); // sign with CA private key

        // build() creates an X509CertificateHolder — BC's internal cert representation
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        // Convert BC holder to standard JCA X509Certificate
        // JcaX509CertificateConverter bridges BC world to Java JCA world
        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);

        System.out.println("✔ CA Certificate built and signed!\n");
        return cert;
    }

    // =========================================================================
    // Step 3 — Inspect the Certificate
    // =========================================================================

    /**
     * Prints all meaningful fields of an X.509 certificate.
     *
     * <p><b>WHY inspect fields?</b><br>
     * PKI expert banne ke liye certificate ke har field ka matlab aana chahiye.
     * Jab EJBCA ya OpenSSL se cert milti hai, tum yahi fields verify karte ho
     * ensure karne ke liye ki profile correctly applied hua hai.</p>
     *
     * @param cert the X.509 certificate to inspect
     */
    public static void printCertificateDetails(X509Certificate cert) {
        System.out.println("📋 Certificate Details:");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");

        // Version — should be 3 (v3) for any cert with extensions
        System.out.println("   │ Version         : v" + cert.getVersion());

        // Serial Number — unique identifier at this CA
        System.out.println("   │ Serial Number   : " + cert.getSerialNumber());

        // Subject DN — who this cert belongs to
        System.out.println("   │ Subject         : " + cert.getSubjectX500Principal().getName());

        // Issuer DN — who signed this cert (same as subject for self-signed)
        System.out.println("   │ Issuer          : " + cert.getIssuerX500Principal().getName());

        // Validity period — MUST check this in production
        System.out.println("   │ Not Before      : " + cert.getNotBefore());
        System.out.println("   │ Not After       : " + cert.getNotAfter());

        // Signature Algorithm — how the cert was signed
        System.out.println("   │ Sig Algorithm   : " + cert.getSigAlgName());

        // Public Key info
        System.out.println("   │ Public Key Alg  : " + cert.getPublicKey().getAlgorithm());
        System.out.printf( "   │ Public Key Size : %d bytes (encoded)%n",
            cert.getPublicKey().getEncoded().length);

        // BasicConstraints — is this a CA?
        // getBasicConstraints() returns pathLenConstraint if CA, -1 if not CA
        int pathLen = cert.getBasicConstraints();
        System.out.println("   │ IsCA            : " + (pathLen >= 0 ? "YES (pathLen=" + pathLen + ")" : "NO (end-entity)"));

        // KeyUsage bits — decoded to human-readable
        boolean[] ku = cert.getKeyUsage();
        if (ku != null) {
            System.out.println("   │ Key Usage       : "
                + (ku[5] ? "keyCertSign " : "")   // bit 5
                + (ku[6] ? "cRLSign " : "")        // bit 6
                + (ku[0] ? "digitalSignature" : "")); // bit 0
        }

        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 4 — Verify Certificate Signature
    // =========================================================================

    /**
     * Verifies that the CA certificate's signature is valid using its own public key.
     *
     * <p><b>WHY verify self-signed cert with its own public key?</b><br>
     * For a self-signed cert, the issuer == subject, so we use the cert's OWN
     * public key to verify the signature. This confirms that:
     * (1) The cert structure was not tampered with after signing
     * (2) The private key that signed it matches the public key in the cert
     * This is the fundamental integrity check done by every TLS client
     * when validating a certificate chain.</p>
     *
     * <p><b>In real chain validation:</b><br>
     * Child cert is verified using the PARENT CA's public key, not its own.
     * {@code cert.verify(issuerCert.getPublicKey())}</p>
     *
     * @param cert the self-signed CA certificate to verify
     * @throws Exception if verification fails (cert is invalid/tampered)
     */
    public static void verifyCertSignature(X509Certificate cert) throws Exception {
        System.out.println("🔍 Verifying Certificate Signature...");

        try {
            // verify() checks that the digital signature in the certificate
            // was created by the private key corresponding to the given public key.
            // For self-signed: use the cert's own public key.
            // Throws CertificateException, SignatureException, etc. if invalid.
            cert.verify(cert.getPublicKey(), Security.getProvider("BC"));

            System.out.println("   ✅ Signature VALID — certificate integrity confirmed!");
            System.out.println("   The private key that signed this cert matches the public key inside it.");
        } catch (Exception e) {
            System.out.println("   ❌ Signature INVALID — cert was tampered or key mismatch!");
            throw e;
        }
        System.out.println();
    }
}
