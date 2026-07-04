package com.pqc.ca;

import com.pqc.Task01_RsaKeyPairGeneration;
import org.bouncycastle.asn1.DEROctetString;
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
 * SubCa — Subordinate (Intermediate) Certificate Authority
 * =========================================================================
 *
 * <h2>Kya Seekhenge?</h2>
 * <p>
 * Sub CA (Subordinate CA / Intermediate CA) banana — jo Root CA se issue
 * hoti hai aur end-entity certificates (TLS, S/MIME, Code Signing) issue
 * karti hai. Sub CA aur Root CA ke beech ka farq samjhenge.
 * </p>
 *
 * <h2>Root CA vs Sub CA — Core Differences</h2>
 * <pre>
 * ┌──────────────────────┬────────────────────┬─────────────────────┐
 * │ Property             │ Root CA            │ Sub CA              │
 * ├──────────────────────┼────────────────────┼─────────────────────┤
 * │ Self-signed?         │ YES                │ NO (Root signs it)  │
 * │ Subject == Issuer?   │ YES                │ NO                  │
 * │ Key Size             │ RSA-4096           │ RSA-2048            │
 * │ Validity             │ 20 years           │ 10 years            │
 * │ pathLenConstraint    │ 1                  │ 0 (end-entity only) │
 * │ Online?              │ NO (offline vault) │ YES (online)        │
 * │ Signs what?          │ Sub CA certs only  │ End-entity certs    │
 * │ If compromised       │ Whole PKI dead     │ Revoke Sub CA only  │
 * └──────────────────────┴────────────────────┴─────────────────────┘
 * </pre>
 *
 * <h2>New Extensions (Not in Root CA)</h2>
 * <ul>
 *   <li><b>CRL Distribution Points (CDP)</b> — Sub CA certificate mein URL
 *       hota hai jahan se verifiers Root CA ki CRL download kar sakte hain.
 *       Agar Sub CA revoke ho jaaye toh Root CA CRL update karti hai.</li>
 *   <li><b>Authority Information Access (AIA)</b> — Do URLs:
 *       (1) OCSP Responder URL — real-time revocation check ke liye
 *       (2) CA Issuers URL — Root CA certificate download karne ke liye
 *       (chain building mein help karta hai)</li>
 * </ul>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.ca.CaHierarchyDemo</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-07-04
 * @see     RootCa          — issues this Sub CA certificate
 * @see     CaHierarchyDemo — runs Root CA + Sub CA together and verifies chain
 * @see     CaStore         — stores both CA key pairs and certificates
 */
public class SubCa {

    /**
     * Sub CA validity: 10 years.
     *
     * <p>WHY 10 years? Sub CA must expire BEFORE Root CA (Root = 20 years).
     * Standard practice: Root 20y → Sub CA 10y → End-entity 1-3y.
     * Each level's lifetime is shorter than the level above it.</p>
     */
    private static final int SUB_CA_VALIDITY_YEARS = 10;

    /**
     * Sub CA RSA key size: 2048 bits.
     *
     * <p>WHY 2048 (not 4096 like Root CA)?
     * <ol>
     *   <li>Sub CA signs thousands of end-entity certs — smaller key = faster signing</li>
     *   <li>Sub CA validity is only 10 years — RSA-2048 is safe through 2030</li>
     *   <li>Root CA is 4096 because it lives 20 years and is the ultimate trust anchor</li>
     * </ol>
     * In modern PKI, EC P-384 is preferred for Sub CAs (even faster, smaller certs).
     * We use RSA-2048 here to keep algorithm consistent for learning.</p>
     */
    private static final int SUB_CA_KEY_SIZE = 2048;

    /**
     * Sub CA serial number — randomly generated.
     *
     * <p>WHY random? Root CA issues multiple Sub CA certs over its lifetime.
     * Serial must be UNIQUE within the issuing CA. Secure random BigInteger
     * prevents serial number prediction attacks (RFC 5280 §4.1.2.2).
     * 64-bit random serial = ~1.8 × 10^19 unique values — sufficient.</p>
     */
    private static final BigInteger SUB_CA_SERIAL =
        new BigInteger(64, new SecureRandom());

    /**
     * Placeholder CRL Distribution Point URL.
     *
     * <p>In production: This is the actual URL where Root CA publishes its CRL.
     * Example: "http://crl.mycompany.com/root-ca.crl"
     * Browsers/clients download this CRL to check if the Sub CA is revoked.</p>
     */
    private static final String ROOT_CRL_URL = "http://crl.pqc-demo.internal/root-ca.crl";

    /**
     * Placeholder OCSP Responder URL.
     *
     * <p>In production: OCSP server URL for real-time revocation status.
     * Example: "http://ocsp.mycompany.com"
     * Clients send OCSP Request → OCSP Responder checks DB → returns status.</p>
     */
    private static final String OCSP_URL = "http://ocsp.pqc-demo.internal";

    /**
     * Placeholder CA Issuers URL (for Root CA cert download).
     *
     * <p>Chain builders download Root CA cert from this URL when it's not
     * in their local trust store. RFC 5280 AIA extension supports this.</p>
     */
    private static final String ROOT_CERT_URL = "http://ca.pqc-demo.internal/root-ca.cer";

    // =========================================================================
    // Entry Point
    // =========================================================================

    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Sub CA — Subordinate Certificate Authority Creation");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // Root CA must exist before Sub CA can be created
        if (CaStore.rootCaKeyPair == null || CaStore.rootCaCert == null) {
            System.out.println("⚙️  Root CA not found in CaStore — creating Root CA first...\n");
            KeyPair rootKeyPair = RootCa.generateRootCaKeyPair();
            X509Certificate rootCert = RootCa.buildRootCaCertificate(rootKeyPair);
            CaStore.rootCaKeyPair = rootKeyPair;
            CaStore.rootCaCert    = rootCert;
        }

        // Step 1: Generate Sub CA key pair
        KeyPair subKeyPair = generateSubCaKeyPair();

        // Step 2: Build Sub CA certificate (signed by Root CA)
        X509Certificate subCert = buildSubCaCertificate(
            subKeyPair,
            CaStore.rootCaKeyPair,
            CaStore.rootCaCert
        );

        // Step 3: Inspect and verify
        printCertificateDetails(subCert);
        verifySubCaCertificate(subCert, CaStore.rootCaCert);

        // Step 4: Store
        CaStore.subCaKeyPair = subKeyPair;
        CaStore.subCaCert    = subCert;

        System.out.println("✅ Sub CA created and verified against Root CA!");
    }

    // =========================================================================
    // Step 1 — Generate Sub CA Key Pair (RSA-2048)
    // =========================================================================

    /**
     * Generates RSA-2048 key pair for the Sub CA.
     *
     * <p><b>Production note:</b><br>
     * Sub CA key pair is also HSM-generated but on an ONLINE HSM (unlike Root CA's
     * offline HSM). The HSM is network-connected to allow the CA software (EJBCA,
     * Vault PKI, etc.) to call it for signing operations.</p>
     *
     * @return RSA-2048 {@link KeyPair} for the Sub CA
     * @throws Exception if key generation fails
     */
    public static KeyPair generateSubCaKeyPair() throws Exception {
        System.out.println("🔑 Generating Sub CA RSA-" + SUB_CA_KEY_SIZE + " Key Pair...");

        long start = System.currentTimeMillis();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(SUB_CA_KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        System.out.printf("✔ RSA-%d Sub CA key pair generated in %d ms%n%n",
            SUB_CA_KEY_SIZE, System.currentTimeMillis() - start);
        return keyPair;
    }

    // =========================================================================
    // Step 2 — Build Sub CA Certificate (Signed by Root CA)
    // =========================================================================

    /**
     * Builds the Sub CA X.509v3 certificate, signed by the Root CA's private key.
     *
     * <p><b>Alag kya hai yahan Root CA se?</b>
     * <ol>
     *   <li>Issuer = Root CA DN (not self)</li>
     *   <li>Signed with Root CA's PRIVATE key (not Sub CA's own key)</li>
     *   <li>pathLen = 0 (Sub CA can issue end-entity only, no further CAs)</li>
     *   <li>AKID references Root CA's public key (not its own)</li>
     *   <li>CDP extension: where to find Root CA's CRL</li>
     *   <li>AIA extension: OCSP URL + Root CA cert download URL</li>
     * </ol>
     * </p>
     *
     * @param subCaKeyPair  Sub CA's own key pair (public key goes in cert)
     * @param rootKeyPair   Root CA's key pair (private key SIGNS the cert)
     * @param rootCaCert    Root CA certificate (DN + public key for AKID)
     * @return signed {@link X509Certificate} for the Sub CA
     * @throws Exception if building or signing fails
     */
    public static X509Certificate buildSubCaCertificate(KeyPair subCaKeyPair,
                                                         KeyPair rootKeyPair,
                                                         X509Certificate rootCaCert)
            throws Exception {

        System.out.println("📜 Building Sub CA Certificate (signed by Root CA)...");

        // ---- Sub CA Subject DN ----
        X500Name subCaDn  = buildSubCaDn();

        // ---- Issuer DN = Root CA's Subject DN ----
        // WHY? X.509 chain rule: cert's Issuer DN must match signer's Subject DN.
        // Root CA's DN is the Issuer of this Sub CA cert.
        X500Name rootCaDn = X500Name.getInstance(
            rootCaCert.getSubjectX500Principal().getEncoded()
        );

        System.out.println("   Sub CA Subject : " + subCaDn);
        System.out.println("   Issuer (Root)  : " + rootCaDn);

        // ---- Validity ----
        Instant now      = Instant.now();
        Date    notBefore = Date.from(now);
        Date    notAfter  = Date.from(now.plus(SUB_CA_VALIDITY_YEARS * 365L, ChronoUnit.DAYS));
        System.out.printf("   Validity        : %s → %s%n", notBefore, notAfter);
        System.out.println("   Serial Number  : " + SUB_CA_SERIAL);

        // ---- Certificate Builder ----
        // Issuer = rootCaDn (NOT subCaDn — this is the key difference from self-signed)
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            rootCaDn,                    // issuer = Root CA's DN
            SUB_CA_SERIAL,               // unique random serial
            notBefore,
            notAfter,
            subCaDn,                     // subject = Sub CA's own DN
            subCaKeyPair.getPublic()     // Sub CA's public key (NOT Root CA's)
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // ---- Extension 1: BasicConstraints — CRITICAL ----
        // isCA = true   : yeh bhi ek CA hai
        // pathLen = 0   : sirf end-entity certificates issue kar sakti hai
        //                 NO further Sub CAs below this level
        // WHY 0 and not 1? Two-tier hierarchy mein Sub CA leaf CA hoti hai.
        // pathLen=0 enforces this — prevents someone from creating rogue Sub-Sub CAs.
        builder.addExtension(
            Extension.basicConstraints,
            true,                        // critical — MUST be for CA certs
            new BasicConstraints(0)      // isCA=true, pathLen=0
        );

        // ---- Extension 2: Key Usage — CRITICAL ----
        // Same as Root CA: keyCertSign + cRLSign only.
        // Sub CA signs end-entity certs (keyCertSign) and issues CRLs (cRLSign).
        builder.addExtension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        );

        // ---- Extension 3: Subject Key Identifier (SKID) ----
        // Hash of Sub CA's OWN public key.
        // End-entity certificates will reference THIS SKID in their AKID.
        builder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(subCaKeyPair.getPublic())
        );

        // ---- Extension 4: Authority Key Identifier (AKID) ----
        // References ROOT CA's public key — not Sub CA's own.
        // WHY? AKID answers: "which issuer key signed this cert?"
        // Chain builder uses AKID to find the parent cert (Root CA) efficiently.
        // AKID = hash of Root CA's public key = Root CA's SKID value.
        builder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(rootCaCert.getPublicKey())
        );

        // ---- Extension 5: CRL Distribution Points (CDP) ----
        // URL jahan Root CA ki CRL publish hoti hai.
        // Verifiers download karke check karte hain: kya yeh Sub CA revoked hai?
        // WHY in Sub CA cert? Sub CA ki revocation Root CA ki CRL mein hoti hai.
        // WHY not in Root CA cert? Root CA revocation = manual out-of-band process.
        //
        // CDP structure:
        //   DistributionPoint → FullName → GeneralName (URI)
        GeneralName           crlUri     = new GeneralName(GeneralName.uniformResourceIdentifier, ROOT_CRL_URL);
        GeneralNames          crlNames   = new GeneralNames(crlUri);
        DistributionPointName dpName     = new DistributionPointName(crlNames);
        DistributionPoint     dp         = new DistributionPoint(dpName, null, null);
        CRLDistPoint          crlDistPt  = new CRLDistPoint(new DistributionPoint[]{dp});

        builder.addExtension(
            Extension.cRLDistributionPoints,
            false,                       // not critical per RFC 5280
            crlDistPt
        );

        // ---- Extension 6: Authority Information Access (AIA) ----
        // Two access descriptions:
        //   (1) OCSP: real-time revocation check server URL
        //   (2) caIssuers: URL to download Root CA certificate
        //       (for chain building when Root CA cert not locally available)
        //
        // WHY AIA matters?
        //   Browser → download Sub CA cert → finds AIA → downloads Root CA cert
        //   → builds complete chain → validates signatures up to trust anchor
        AccessDescription ocspAccess = new AccessDescription(
            AccessDescription.id_ad_ocsp,
            new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL)
        );
        AccessDescription caIssuersAccess = new AccessDescription(
            AccessDescription.id_ad_caIssuers,
            new GeneralName(GeneralName.uniformResourceIdentifier, ROOT_CERT_URL)
        );
        AuthorityInformationAccess aia = new AuthorityInformationAccess(
            new AccessDescription[]{ ocspAccess, caIssuersAccess }
        );

        builder.addExtension(
            Extension.authorityInfoAccess,
            false,                       // not critical
            aia
        );

        // ---- Sign with ROOT CA's PRIVATE KEY ----
        // IMPORTANT: Sub CA cert is signed by ROOT CA's private key — NOT Sub CA's!
        // Root CA private key ko use karke Sub CA ko "authorize" kia ja raha hai.
        // Yeh hi trust ka actual transfer hai Root CA se Sub CA ko.
        ContentSigner rootSigner = new JcaContentSignerBuilder("SHA384withRSA")
            .setProvider("BC")
            .build(rootKeyPair.getPrivate());   // ← ROOT CA's private key

        X509CertificateHolder certHolder = builder.build(rootSigner);

        X509Certificate subCaCert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);

        System.out.println("✔ Sub CA Certificate built — signed with Root CA private key!\n");
        return subCaCert;
    }

    // =========================================================================
    // Helper — Distinguished Name
    // =========================================================================

    /**
     * Builds the Sub CA Distinguished Name.
     *
     * <p><b>Sub CA DN Best Practices:</b>
     * <ul>
     *   <li>CN clearly indicates "Sub CA" or "Issuing CA" — distinguishes from Root CA</li>
     *   <li>O = same as Root CA (same organization)</li>
     *   <li>OU = department responsible for this CA (e.g., "PKI Infrastructure")</li>
     *   <li>Sub CA DN must be DIFFERENT from Root CA DN — X.509 name collision = chain error</li>
     * </ul>
     * </p>
     *
     * @return {@link X500Name} for the Sub CA
     */
    public static X500Name buildSubCaDn() {
        return new X500Name(
            "CN=PQC Demo Issuing CA 1," +
            "OU=PKI Infrastructure," +
            "O=PQC Demo Organization," +
            "C=IN"
        );
    }

    // =========================================================================
    // Step 3 — Inspect Sub CA Certificate
    // =========================================================================

    /**
     * Prints Sub CA certificate details with explanations.
     *
     * @param cert Sub CA certificate to inspect
     */
    public static void printCertificateDetails(X509Certificate cert) {

        System.out.println("📋 Sub CA Certificate Details:");
        System.out.println("   ┌──────────────────────────────────────────────────────────┐");
        System.out.println("   │ Version         : v" + cert.getVersion());
        System.out.println("   │ Serial Number   : " + cert.getSerialNumber());
        System.out.println("   │ Subject         : " + cert.getSubjectX500Principal().getName());
        System.out.println("   │ Issuer          : " + cert.getIssuerX500Principal().getName());
        System.out.println("   │ Not Before      : " + cert.getNotBefore());
        System.out.println("   │ Not After       : " + cert.getNotAfter());
        System.out.println("   │ Sig Algorithm   : " + cert.getSigAlgName());

        java.security.interfaces.RSAPublicKey rsaPub =
            (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
        System.out.printf("   │ Key             : RSA-%d%n", rsaPub.getModulus().bitLength());

        int pathLen = cert.getBasicConstraints();
        System.out.println("   │ Is CA           : " + (pathLen >= 0 ? "YES" : "NO"));
        System.out.println("   │ Path Length     : " + (pathLen >= 0
            ? pathLen + " (end-entity only — no further Sub CAs)"
            : "N/A"));

        boolean[] ku = cert.getKeyUsage();
        if (ku != null) {
            System.out.println("   │ Key Usage       : "
                + (ku[5] ? "keyCertSign " : "")
                + (ku[6] ? "cRLSign" : ""));
        }

        // Check Subject != Issuer (should NOT be self-signed)
        boolean selfSigned = cert.getSubjectX500Principal()
            .equals(cert.getIssuerX500Principal());
        System.out.println("   │ Self-Signed     : " + (selfSigned
            ? "YES (unexpected for Sub CA!)"
            : "NO — signed by Root CA ✓"));

        System.out.println("   └──────────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 4 — Verify Sub CA Certificate using Root CA's Public Key
    // =========================================================================

    /**
     * Verifies the Sub CA certificate using the ROOT CA's public key.
     *
     * <p><b>Chain verification logic:</b><br>
     * {@code subCaCert.verify(rootCaCert.getPublicKey())} — we use the ISSUER's
     * (Root CA's) public key to verify the signature on the Sub CA cert.
     * This confirms: Root CA's private key created this signature = Root CA authorized
     * this Sub CA = trust is delegated from Root CA to Sub CA.</p>
     *
     * <p><b>This is the exact same check done by TLS clients</b> when verifying
     * a certificate chain: each cert is verified using its issuer's public key.</p>
     *
     * @param subCaCert Sub CA certificate to verify
     * @param rootCaCert Root CA certificate (provides the public key for verification)
     * @throws Exception if verification fails
     */
    public static void verifySubCaCertificate(X509Certificate subCaCert,
                                               X509Certificate rootCaCert) throws Exception {
        System.out.println("🔍 Verifying Sub CA Certificate using Root CA's public key...");
        try {
            // Use ROOT CA's public key to verify SUB CA cert signature.
            // NOT subCaCert.getPublicKey() — that would verify a self-signed cert.
            subCaCert.verify(rootCaCert.getPublicKey(), Security.getProvider("BC"));

            System.out.println("   ✅ Sub CA certificate signature VALID");
            System.out.println("   → Root CA's private key created this signature");
            System.out.println("   → Sub CA is authorized by Root CA ✓\n");
        } catch (Exception e) {
            System.out.println("   ❌ Verification FAILED: " + e.getMessage());
            throw e;
        }
    }
}
