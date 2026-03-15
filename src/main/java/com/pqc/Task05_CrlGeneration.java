package com.pqc;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * =========================================================================
 * Task 05 — CRL (Certificate Revocation List) Generation
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * CRL (Certificate Revocation List) ek signed list hai jisme CA batata hai
 * ki konse certificates "revoke" ho gaye — aur kyun. Client (browser, server)
 * CRL download karke check karta hai ki certificate abhi bhi valid hai ya nahi.
 * RA system revocation requests process karta hai aur CA ko forward karta hai.
 * </p>
 *
 * <h2>CRL Kyun Zaroori Hai?</h2>
 * <p>
 * Certificate ki validity period khatam hone se pehle bhi cert invalid ho
 * sakti hai — key compromise, employee left, wrong data issued, etc.
 * CRL is the traditional mechanism to communicate revoked certs.
 * (Modern alternative: OCSP — Task06)
 * </p>
 *
 * <h2>CRL Structure (RFC 5280)</h2>
 * <pre>
 * CertificateList {
 *   TBSCertList {
 *     version         = v2 (1) — required for extensions
 *     signature       = algorithm identifier
 *     issuer          = CA's DN
 *     thisUpdate      = when this CRL was published
 *     nextUpdate      = when next CRL is expected (clients check before this)
 *     revokedCerts[]  = list of { serialNumber, revocationDate, extensions }
 *     extensions {
 *       cRLNumber           = monotonically increasing integer
 *       authorityKeyIdentifier = links to signing CA
 *     }
 *   }
 *   signatureAlgorithm = SHA384withRSA
 *   signature          = CA's signature over TBSCertList
 * }
 * </pre>
 *
 * <h2>CRL vs OCSP (Quick Comparison)</h2>
 * <pre>
 * CRL                          OCSP (Task06)
 * ─────────────────────────    ──────────────────────────────────
 * Full list download           Per-cert real-time query
 * Large file, slow update      Small response, near real-time
 * Offline capability           Requires OCSP responder online
 * Standard for PKI             Standard for TLS/browsers
 * CA publishes periodically    RA/CA responds on demand
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task05_CrlGeneration</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class Task05_CrlGeneration {

    /**
     * CRL validity period in hours.
     *
     * <p>WHY 24 hours? CRL nextUpdate = thisUpdate + validity period.
     * Clients MUST NOT use a CRL past its nextUpdate time.
     * 24 hours is a typical schedule for enterprise PKI CRLs.
     * High-security PKI (government, banking) may publish every 1-4 hours.
     * CRL caches in browsers typically honor nextUpdate.</p>
     */
    private static final int CRL_VALIDITY_HOURS = 24;

    /**
     * Entry point — builds and signs a CRL with one revoked certificate.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if CRL generation fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 05 — CRL (Certificate Revocation List) Generation");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // Ensure prerequisites
        if (CertificateStore.entityCert == null) {
            Task04_IssueCertFromCsr.main(new String[]{});
        }

        // Step 1: Build CRL with one revoked certificate
        X509CRL crl = buildCrl(
            CertificateStore.entityCert.getSerialNumber(),
            CRLReason.lookup(CRLReason.keyCompromise)  // Reason: private key was compromised
        );

        // Step 2: Verify CRL signature
        verifyCrl(crl);

        // Step 3: Print CRL details
        printCrlDetails(crl);

        // Step 4: Check if our issued cert appears as revoked
        checkCertRevoked(crl, CertificateStore.entityCert.getSerialNumber());

        // Step 5: Export CRL as PEM
        printCrlPem(crl);

        System.out.println("✅ Task 05 Complete — CRL generated with revoked certificate!");
        System.out.println("   Next Step → Task06_OcspRequestResponse.java");
    }

    // =========================================================================
    // Step 1 — Build and Sign the CRL
    // =========================================================================

    /**
     * Builds an X.509v2 CRL signed by the CA, revoking the specified certificate.
     *
     * <p><b>WHY JcaX509v2CRLBuilder?</b><br>
     * BouncyCastle's JCA-friendly CRL builder. Takes Java-native types (Date, BigInteger)
     * and produces a standards-compliant RFC 5280 CRL. The "v2" refers to CRL version 2,
     * which supports extensions (CRLNumber, AKI, DeltaCRL indicators).</p>
     *
     * <p><b>Revocation Reasons (RFC 5280 §5.3.1):</b>
     * <ul>
     *   <li>{@code unspecified(0)}      — reason not stated</li>
     *   <li>{@code keyCompromise(1)}    — private key compromised — MOST CRITICAL</li>
     *   <li>{@code cACompromise(2)}     — CA key compromised</li>
     *   <li>{@code affiliationChanged(3)} — subscriber changed org/department</li>
     *   <li>{@code superseded(4)}       — new cert replaces this one</li>
     *   <li>{@code cessationOfOperation(5)} — entity no longer needs cert</li>
     *   <li>{@code certificateHold(6)}  — temporarily suspended (onHold)</li>
     *   <li>{@code removeFromCRL(8)}    — restores a certificateHold entry</li>
     * </ul>
     * </p>
     *
     * @param revokedSerial  serial number of the certificate to revoke
     * @param revocationReason CRL reason code (RFC 5280 §5.3.1)
     * @return the signed {@link X509CRL}
     * @throws Exception if CRL construction or signing fails
     */
    public static X509CRL buildCrl(BigInteger revokedSerial,
                                    CRLReason revocationReason) throws Exception {
        System.out.println("📋 Building CRL...");

        // ---- CRL Issuer ----
        // MUST match the CA cert's Subject DN exactly
        // WHY? Clients match CRL to the CA cert by comparing issuer names
        X500Name issuerDn = new X500Name(
            CertificateStore.caCert.getSubjectX500Principal().getName()
        );

        // ---- thisUpdate / nextUpdate ----
        Instant now       = Instant.now();
        Date    thisUpdate = Date.from(now);
        // nextUpdate: when clients should fetch the next CRL
        // Clients treat certificates as possibly revoked if CRL has expired
        Date    nextUpdate = Date.from(now.plus(CRL_VALIDITY_HOURS, ChronoUnit.HOURS));
        System.out.println("   thisUpdate : " + thisUpdate);
        System.out.println("   nextUpdate : " + nextUpdate);

        // ---- Create CRL Builder ----
        // JcaX509v2CRLBuilder(issuerDN, thisUpdate)
        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerDn, thisUpdate);

        // setNextUpdate: clients must refresh before this time
        crlBuilder.setNextUpdate(nextUpdate);

        // ---- Add Revoked Certificate Entry ----
        // addCRLEntry(serial, revocationDate, reasonCode)
        // revocationDate = when the cert was revoked (should be in the past if already compromised)
        // WHY current time? In this demo, revocation is happening "now"
        crlBuilder.addCRLEntry(
            revokedSerial,                          // serial of the revoked cert
            Date.from(now),                         // when revocation took effect
            revocationReason.getValue().intValue()  // reason code integer
        );
        System.out.println("   Added revoked serial: 0x" + revokedSerial.toString(16)
            + " reason: " + revocationReason);

        // ---- CRL Extensions ----
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // Extension 1: AuthorityKeyIdentifier
        // Links this CRL to the signing CA. Clients use this to find the CA
        // cert needed to verify the CRL signature.
        crlBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(CertificateStore.caCert)
        );

        // Extension 2: CRLNumber — monotonically increasing integer
        // WHY? Clients use CRLNumber to detect if they have the LATEST CRL.
        // If cached CRL number < new CRL number, refresh the cache.
        // For this demo we use 1; production systems auto-increment per database.
        crlBuilder.addExtension(
            Extension.cRLNumber,
            false,
            new CRLNumber(BigInteger.ONE)  // CRL sequence number = 1
        );

        // ---- Sign the CRL ----
        // CA private key signs the CRL — same key that signs certificates
        // WHY? KC cert has KeyUsage cRLSign bit set (Task02) authorizing this
        ContentSigner caSigner = new JcaContentSignerBuilder("SHA384withRSA")
            .setProvider("BC")
            .build(CertificateStore.caKeyPair.getPrivate());

        X509CRLHolder crlHolder = crlBuilder.build(caSigner);

        // Convert to JCA X509CRL
        X509CRL crl = new JcaX509CRLConverter()
            .setProvider("BC")
            .getCRL(crlHolder);

        System.out.println("✔ CRL built and signed by CA!\n");
        return crl;
    }

    // =========================================================================
    // Step 2 — Verify CRL Signature
    // =========================================================================

    /**
     * Verifies the CRL's signature using the CA's public key.
     *
     * <p><b>WHY verify?</b><br>
     * An attacker could forge a CRL to either remove revoked certs (making
     * compromised certs appear valid) or add valid certs to the revoked list
     * (denial of service). Signature verification prevents both attacks.
     * Clients MUST verify CRL signature before trusting its contents.</p>
     *
     * @param crl the CRL to verify
     * @throws Exception if signature verification fails
     */
    public static void verifyCrl(X509CRL crl) throws Exception {
        System.out.println("🔍 Verifying CRL signature...");
        try {
            // verify(PublicKey) — checks CRL signature against CA's public key
            // crl.getIssuerX500Principal() should match CertificateStore.caCert.getSubjectX500Principal()
            crl.verify(CertificateStore.caCert.getPublicKey(),
                       java.security.Security.getProvider("BC"));
            System.out.println("   ✅ CRL signature VALID — CA correctly signed this CRL!");
        } catch (Exception e) {
            System.out.println("   ❌ CRL signature INVALID: " + e.getMessage());
            throw e;
        }
        System.out.println();
    }

    // =========================================================================
    // Step 3 — Print CRL Details
    // =========================================================================

    /**
     * Prints the decoded CRL fields for learning and debugging.
     *
     * @param crl the X.509 CRL to inspect
     */
    public static void printCrlDetails(X509CRL crl) {
        System.out.println("📋 CRL Details:");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");

        // getVersion() returns 1 for v1, 2 for v2 (note: v2 CRL = version field value 1)
        System.out.println("   │ Version        : v" + (crl.getVersion()));

        // Issuer — must match the CA's subject
        System.out.println("   │ Issuer         : " + crl.getIssuerX500Principal().getName());

        // Signature algorithm
        System.out.println("   │ Sig Algorithm  : " + crl.getSigAlgName());

        // thisUpdate + nextUpdate — validity window
        System.out.println("   │ This Update    : " + crl.getThisUpdate());
        System.out.println("   │ Next Update    : " + crl.getNextUpdate());

        // Count of revoked entries
        int count = crl.getRevokedCertificates() == null ? 0
            : crl.getRevokedCertificates().size();
        System.out.println("   │ Revoked Certs  : " + count);

        // Print each revoked entry's serial and reason
        if (crl.getRevokedCertificates() != null) {
            for (X509CRLEntry entry : crl.getRevokedCertificates()) {
                System.out.printf("   │   ├── Serial: 0x%s  Revoked: %s%n",
                    entry.getSerialNumber().toString(16),
                    entry.getRevocationDate());
            }
        }

        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 4 — Check if a Specific Certificate is Revoked
    // =========================================================================

    /**
     * Checks whether a specific certificate serial appears in the CRL.
     *
     * <p><b>This is the check clients perform:</b><br>
     * When a TLS client receives a server certificate, it downloads the CRL from
     * the CDP (CRL Distribution Point) extension in the cert, then calls
     * {@code crl.isRevoked(cert)} to check status. This is what web browsers
     * used to do before OCSP became dominant.</p>
     *
     * @param crl           the CRL to check against
     * @param serialNumber  the certificate serial to look up
     */
    public static void checkCertRevoked(X509CRL crl, BigInteger serialNumber) {
        System.out.printf("🔎 Checking if serial 0x%s is revoked...%n", serialNumber.toString(16));

        // getRevokedCertificate(serial) returns the CRL entry if found, null if not
        X509CRLEntry entry = crl.getRevokedCertificate(serialNumber);

        if (entry != null) {
            System.out.println("   🚫 Certificate IS revoked!");
            System.out.println("   Revocation Date  : " + entry.getRevocationDate());
            // getRevocationReason() parses the CRLReason extension from the entry
            System.out.println("   Revocation Reason: " + entry.getRevocationReason());
        } else {
            System.out.println("   ✅ Certificate is NOT revoked — still valid (per this CRL).");
        }
        System.out.println();
    }

    // =========================================================================
    // Step 5 — Export CRL as PEM
    // =========================================================================

    /**
     * Exports the CRL in PEM format for distribution.
     *
     * <p><b>CRL distribution in production:</b><br>
     * CRLs are published to a CDP (CRL Distribution Point) URL — an HTTP endpoint
     * that clients download the CRL from. The CDP URL is embedded in every issued
     * certificate as the {@code cRLDistributionPoints} extension.
     * Example: {@code http://crl.company.com/RootCA.crl}</p>
     *
     * <p><b>File format:</b> DER-encoded CRL = binary. PEM-encoded CRL = Base64 text.
     * Most tools accept both. NGINX, Apache, Java TrustManager accept DER directly.</p>
     *
     * @param crl the CRL to export
     * @throws Exception if DER encoding fails
     */
    public static void printCrlPem(X509CRL crl) throws Exception {
        // getEncoded() = DER bytes of the CRL
        byte[] derBytes = crl.getEncoded();

        String pem = "-----BEGIN X509 CRL-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(derBytes)
            + "\n-----END X509 CRL-----";

        System.out.println("📄 CRL in PEM Format (publish to CDP URL):");
        System.out.println(pem);
        System.out.printf("%n   CRL DER size: %d bytes (would grow with more revoked entries)%n%n",
            derBytes.length);
    }
}
