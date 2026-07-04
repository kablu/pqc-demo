package com.pqc.ca;

import com.pqc.Task01_RsaKeyPairGeneration;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * =========================================================================
 * RootCa — Self-Signed Root Certificate Authority
 * =========================================================================
 *
 * <h2>Kya Seekhenge?</h2>
 * <p>
 * Root CA banana — PKI hierarchy ka sabse upar ka trust anchor. Root CA
 * self-signed hoti hai (khud ko khud sign karti hai) kyunki koi aur CA
 * nahi hoti upar. Ispar poori PKI ki trust depend karti hai.
 * </p>
 *
 * <h2>Root CA ka Task02 se Farq</h2>
 * <pre>
 * Task02 (Basic):                    RootCa (Production-grade):
 *   pathLen = 0 (no Sub CA)            pathLen = 1 (allows one Sub CA level)
 *   No SubjectKeyIdentifier            SubjectKeyIdentifier added
 *   No AuthorityKeyIdentifier          AuthorityKeyIdentifier added (self-ref)
 *   Validity: 10 years                 Validity: 20 years (root lives longer)
 *   No certificate policies            CertificatePolicies added
 * </pre>
 *
 * <h2>Extensions Explained</h2>
 * <ul>
 *   <li><b>BasicConstraints</b> — isCA=true, pathLen=1: yeh CA hai aur ek
 *       level ka Sub CA issue kar sakti hai</li>
 *   <li><b>KeyUsage</b> — keyCertSign + cRLSign: sirf yahi do kaam karegi</li>
 *   <li><b>SubjectKeyIdentifier (SKID)</b> — public key ka hash. Dusre
 *       certificates is SKID ko AuthorityKeyIdentifier mein reference karte hain</li>
 *   <li><b>AuthorityKeyIdentifier (AKID)</b> — self-signed mein apna hi SKID
 *       reference karta hai. Chain verification mein help karta hai</li>
 * </ul>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.ca.CaHierarchyDemo</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-07-04
 * @see     SubCa    — Sub CA issued by this Root CA
 * @see     CaStore  — shared state between Root CA and Sub CA
 */
public class RootCa {

    /**
     * Root CA validity: 20 years.
     *
     * <p>WHY 20 years? Root CA must outlive ALL certificates in the hierarchy.
     * Sub CA: 10 years. End-entity: 1-3 years. So Root needs to be valid
     * when the last Sub CA expires + its last issued cert expires.
     * Real-world roots: DigiCert Global Root G2 = 25 years, Let's Encrypt = 20 years.</p>
     */
    private static final int ROOT_VALIDITY_YEARS = 20;

    /**
     * Root CA key size: RSA-4096.
     *
     * <p>WHY 4096? Root CA key is offline and signs rarely (only Sub CA certs).
     * Performance is not a concern. Security is paramount — RSA-4096 provides
     * ~140 bits of security, safe well beyond 2040 even for quantum-adjacent threats.
     * NIST SP 800-57 recommends 4096 for keys with > 20 year protection.</p>
     */
    private static final int ROOT_KEY_SIZE = 4096;

    /**
     * Root CA serial number.
     *
     * <p>WHY BigInteger.ONE? By convention, Root CA serial is 1. The serial number
     * must be unique WITHIN a CA's issued certificates. Since Root CA issues only
     * Sub CA certs (very few), serial 1 for the Root's own cert is conventional.
     * RFC 5280 §4.1.2.2: serial must be positive integer, max 20 octets.</p>
     */
    private static final BigInteger ROOT_SERIAL = BigInteger.ONE;

    // =========================================================================
    // Entry Point
    // =========================================================================

    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Root CA — Self-Signed Certificate Authority Creation");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // Step 1: Generate Root CA key pair
        KeyPair rootKeyPair = generateRootCaKeyPair();

        // Step 2: Build self-signed Root CA certificate
        X509Certificate rootCert = buildRootCaCertificate(rootKeyPair);

        // Step 3: Print and verify
        printCertificateDetails(rootCert);
        verifySelfSignedCert(rootCert);

        // Step 4: Store for Sub CA usage
        CaStore.rootCaKeyPair = rootKeyPair;
        CaStore.rootCaCert    = rootCert;

        System.out.println("✅ Root CA created! Next → SubCa.java");
    }

    // =========================================================================
    // Step 1 — Generate Root CA Key Pair (RSA-4096)
    // =========================================================================

    /**
     * Generates an RSA-4096 key pair for the Root CA.
     *
     * <p><b>WHY separate method from Task01?</b><br>
     * Root CA key generation in real PKI happens in an offline "Key Ceremony" —
     * a formal, audited, multi-person process. Having a dedicated method
     * makes it clear this is a special, important operation.</p>
     *
     * <p><b>Production note:</b><br>
     * In production, this would NOT generate a Java KeyPair object in memory.
     * Instead: {@code PKCS11KeyPairGenerator} with an HSM slot — the private key
     * is generated inside the HSM and never exported as plaintext bytes ever.</p>
     *
     * @return RSA-4096 {@link KeyPair} for the Root CA
     * @throws Exception if key generation fails
     */
    public static KeyPair generateRootCaKeyPair() throws Exception {
        System.out.println("🔑 Generating Root CA RSA-" + ROOT_KEY_SIZE + " Key Pair...");
        System.out.println("   (In production: HSM-generated, never leaves hardware)");

        long start = System.currentTimeMillis();

        // Explicitly use BouncyCastle provider for consistent behavior.
        // In production with HSM: KeyPairGenerator.getInstance("RSA", pkcs11Provider)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(ROOT_KEY_SIZE, new SecureRandom());

        KeyPair keyPair = keyGen.generateKeyPair();

        System.out.printf("✔ RSA-%d Root CA key pair generated in %d ms%n%n",
            ROOT_KEY_SIZE, System.currentTimeMillis() - start);

        return keyPair;
    }

    // =========================================================================
    // Step 2 — Build Self-Signed Root CA Certificate
    // =========================================================================

    /**
     * Builds the self-signed Root CA X.509v3 certificate.
     *
     * <p><b>Self-signed kya hai?</b><br>
     * Root CA ke certificate mein Subject == Issuer (khud hi khud ka issuer).
     * Signature Root CA ki apni private key se create hoti hai. Verify karne
     * ke liye certificate ke andar ka public key hi use hota hai.</p>
     *
     * <p><b>Extensions kyu zaruri hain?</b><br>
     * RFC 5280 mandate karta hai ki CA certificates mein specific extensions
     * MUST honi chahiye (BasicConstraints critical, KeyUsage critical).
     * Bina in extensions ke koi bhi compliant PKI client certificate reject
     * kar dega as "not a CA certificate".</p>
     *
     * @param rootKeyPair Root CA RSA-4096 key pair
     * @return signed {@link X509Certificate} for the Root CA
     * @throws Exception if building or signing fails
     */
    public static X509Certificate buildRootCaCertificate(KeyPair rootKeyPair) throws Exception {

        System.out.println("📜 Building Root CA Certificate...");

        // ---- Subject / Issuer DN ----
        // Self-signed: subject == issuer (Root CA signs itself)
        X500Name rootDn = buildRootCaDn();
        System.out.println("   Subject/Issuer DN : " + rootDn);

        // ---- Validity ----
        Instant now      = Instant.now();
        Date    notBefore = Date.from(now);
        Date    notAfter  = Date.from(now.plus(ROOT_VALIDITY_YEARS * 365L, ChronoUnit.DAYS));
        System.out.printf("   Validity          : %s → %s%n", notBefore, notAfter);

        // ---- Certificate Builder ----
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            rootDn,                      // issuer  = self (self-signed)
            ROOT_SERIAL,                 // serial  = 1
            notBefore,                   // validity start
            notAfter,                    // validity end (20 years)
            rootDn,                      // subject = self (self-signed)
            rootKeyPair.getPublic()      // Root CA's public key
        );

        // ---- Extension 1: BasicConstraints — CRITICAL ----
        // isCA = true   : yeh ek Certificate Authority hai
        // pathLen = 1   : ek level ka Sub CA issue kar sakti hai
        //                 pathLen=0 hota toh sirf end-entity certs issue kar sakti
        //                 pathLen=1 means: Root→SubCA→EndEntity (2-tier hierarchy)
        // WHY critical? RFC 5280 §4.2.1.9 mandates BasicConstraints MUST be critical
        // for CA certificates. Agar critical nahi toh chain building fail ho sakti hai.
        builder.addExtension(
            Extension.basicConstraints,
            true,                        // critical
            new BasicConstraints(1)      // isCA=true, pathLenConstraint=1
        );

        // ---- Extension 2: Key Usage — CRITICAL ----
        // keyCertSign : Root CA certificates sign kar sakti hai (Sub CA + End Entity)
        // cRLSign     : Root CA CRL (Certificate Revocation List) sign kar sakti hai
        // WHY ONLY these two? Root CA ka kaam sirf certificate signing hai.
        // digitalSignature, keyEncipherment, etc. NAHI chahiye CA ke liye.
        // Minimal key usage = minimum attack surface.
        builder.addExtension(
            Extension.keyUsage,
            true,                        // critical
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        );

        // ---- Extension 3: Subject Key Identifier (SKID) ----
        // SKID = SHA-1 hash of the public key's SubjectPublicKeyInfo bit string.
        // WHY? SKID is used by Sub CA and End-Entity certificates in their
        // AuthorityKeyIdentifier extension to reference which issuer key signed them.
        // Chain builders use SKID/AKID matching to build certificate paths efficiently.
        // NOT critical (RFC 5280 §4.2.1.2: MUST be non-critical)
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(
            Extension.subjectKeyIdentifier,
            false,                       // not critical
            extUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic())
        );

        // ---- Extension 4: Authority Key Identifier (AKID) ----
        // For self-signed Root CA: AKID references Root CA's own SKID.
        // WHY add AKID to self-signed cert? RFC 5280 recommends it for consistency.
        // Chain builders expect AKID in all certs including root.
        // AKID links this cert to the key that signed it — for root = itself.
        builder.addExtension(
            Extension.authorityKeyIdentifier,
            false,                       // not critical
            extUtils.createAuthorityKeyIdentifier(rootKeyPair.getPublic())
        );

        // ---- Sign the Certificate ----
        // SHA384withRSA: SHA-384 digest + RSA PKCS#1 v1.5 signature
        // WHY SHA-384? NIST recommends SHA-384 or SHA-512 for long-lived keys
        // (Root CA cert is valid 20 years). SHA-256 sufficient for end-entity certs.
        // SHA-1 = FORBIDDEN (broken since 2017, browsers reject it).
        ContentSigner signer = new JcaContentSignerBuilder("SHA384withRSA")
            .setProvider("BC")
            .build(rootKeyPair.getPrivate());

        X509CertificateHolder certHolder = builder.build(signer);

        X509Certificate rootCert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);

        System.out.println("✔ Root CA Certificate built and self-signed!\n");
        return rootCert;
    }

    // =========================================================================
    // Helper — Distinguished Name
    // =========================================================================

    /**
     * Builds the Root CA Distinguished Name.
     *
     * <p><b>Root CA DN Best Practices:</b>
     * <ul>
     *   <li>CN should clearly indicate "Root CA" — avoids confusion with Sub CA</li>
     *   <li>O = full legal organization name</li>
     *   <li>C = ISO 3166-1 alpha-2 country code (2 letters)</li>
     *   <li>Root CA DN must be UNIQUE across the PKI — never reuse a Root CA DN</li>
     * </ul>
     * </p>
     *
     * @return {@link X500Name} for the Root CA
     */
    public static X500Name buildRootCaDn() {
        return new X500Name(
            "CN=PQC Demo Root CA," +
            "OU=PKI Infrastructure," +
            "O=PQC Demo Organization," +
            "C=IN"
        );
    }

    // =========================================================================
    // Step 3 — Inspect Certificate
    // =========================================================================

    /**
     * Prints all fields of the Root CA certificate for inspection.
     *
     * @param cert Root CA certificate
     */
    public static void printCertificateDetails(X509Certificate cert) {

        System.out.println("📋 Root CA Certificate Details:");
        System.out.println("   ┌──────────────────────────────────────────────────────────┐");
        System.out.println("   │ Version         : v" + cert.getVersion());
        System.out.println("   │ Serial Number   : " + cert.getSerialNumber());
        System.out.println("   │ Subject         : " + cert.getSubjectX500Principal().getName());
        System.out.println("   │ Issuer          : " + cert.getIssuerX500Principal().getName());
        System.out.println("   │ Not Before      : " + cert.getNotBefore());
        System.out.println("   │ Not After       : " + cert.getNotAfter());
        System.out.println("   │ Sig Algorithm   : " + cert.getSigAlgName());

        // Public key details
        java.security.interfaces.RSAPublicKey rsaPub =
            (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
        System.out.printf("   │ Key             : RSA-%d%n", rsaPub.getModulus().bitLength());

        // BasicConstraints — isCA and pathLen
        int pathLen = cert.getBasicConstraints();
        System.out.println("   │ Is CA           : " + (pathLen >= 0 ? "YES" : "NO"));
        System.out.println("   │ Path Length     : " + (pathLen >= 0 ? pathLen + " (can issue " + pathLen + " Sub CA level/s)" : "N/A"));

        // Key Usage
        boolean[] ku = cert.getKeyUsage();
        if (ku != null) {
            System.out.println("   │ Key Usage       : "
                + (ku[5] ? "keyCertSign " : "")
                + (ku[6] ? "cRLSign" : ""));
        }

        // Self-signed check
        boolean selfSigned = cert.getSubjectX500Principal()
            .equals(cert.getIssuerX500Principal());
        System.out.println("   │ Self-Signed     : " + (selfSigned ? "YES (Root CA)" : "NO (Signed by issuer)"));

        System.out.println("   └──────────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 4 — Verify Self-Signed Certificate
    // =========================================================================

    /**
     * Verifies the Root CA certificate's signature using its own public key.
     *
     * <p><b>Self-signed verification logic:</b><br>
     * For self-signed certs, the public key inside the cert is the SAME key
     * whose corresponding private key created the signature. So we pass
     * {@code cert.getPublicKey()} to {@code cert.verify()}.</p>
     *
     * <p><b>In chain verification (Sub CA / End Entity):</b><br>
     * {@code cert.verify(issuerCert.getPublicKey())} — use the PARENT's
     * public key, not the cert's own key.</p>
     *
     * @param cert Root CA self-signed certificate
     * @throws Exception if signature is invalid
     */
    public static void verifySelfSignedCert(X509Certificate cert) throws Exception {
        System.out.println("🔍 Verifying Root CA Self-Signature...");
        try {
            // Self-signed: verify using cert's own embedded public key
            cert.verify(cert.getPublicKey(), Security.getProvider("BC"));
            System.out.println("   ✅ Root CA self-signature VALID");
            System.out.println("   → Private key matches public key inside the certificate\n");
        } catch (Exception e) {
            System.out.println("   ❌ Signature INVALID: " + e.getMessage());
            throw e;
        }
    }
}
