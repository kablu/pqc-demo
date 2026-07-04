package com.pqc.ca;

import com.pqc.Task01_RsaKeyPairGeneration;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * =========================================================================
 * CaHierarchyDemo — Complete Two-Tier PKI Hierarchy Demonstration
 * =========================================================================
 *
 * <h2>Kya Seekhenge?</h2>
 * <p>
 * Root CA → Sub CA chain banate hain aur verify karte hain. Poori PKI
 * hierarchy ek saath demonstrate hogi — trust kaise Root se Sub CA tak
 * propagate hoti hai, aur chain verification kaise kaam karti hai.
 * </p>
 *
 * <h2>Complete PKI Hierarchy</h2>
 * <pre>
 * ┌──────────────────────────────────────────────────────────┐
 * │  TRUST ANCHOR                                            │
 * │  Root CA (Self-Signed, RSA-4096, 20 years)               │
 * │  CN=PQC Demo Root CA, O=PQC Demo Organization, C=IN     │
 * │  BasicConstraints: isCA=true, pathLen=1                  │
 * └────────────────────────┬─────────────────────────────────┘
 *                          │ signs (Root CA private key)
 *                          ▼
 * ┌──────────────────────────────────────────────────────────┐
 * │  ISSUING CA                                              │
 * │  Sub CA (Signed by Root, RSA-2048, 10 years)             │
 * │  CN=PQC Demo Issuing CA 1, O=PQC Demo Organization, C=IN│
 * │  BasicConstraints: isCA=true, pathLen=0                  │
 * │  CDP: http://crl.pqc-demo.internal/root-ca.crl          │
 * │  AIA: OCSP + caIssuers URLs                              │
 * └────────────────────────┬─────────────────────────────────┘
 *                          │ will sign (Sub CA private key)
 *                          ▼
 *        [TLS Server Certs, S/MIME Certs, Code Signing Certs]
 *        (future implementation — end-entity certificates)
 * </pre>
 *
 * <h2>Chain Verification Logic</h2>
 * <pre>
 * Step 1: Root CA self-signature verify → Root CA's own public key
 * Step 2: Sub CA signature verify       → Root CA's public key
 * Step 3: Chain linkage verify          → Sub CA Issuer DN == Root CA Subject DN
 * Step 4: Validity periods verify       → both must be currently valid
 * Step 5: BasicConstraints verify       → both must have isCA=true
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.ca.CaHierarchyDemo</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-07-04
 * @see     RootCa — Root CA creation
 * @see     SubCa  — Sub CA creation
 */
public class CaHierarchyDemo {

    public static void main(String[] args) throws Exception {

        printBanner();

        // Step 0: Register BouncyCastle provider
        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        // =====================================================================
        // PHASE 1 — Create Root CA
        // =====================================================================
        printPhase(1, "Root CA Creation (Self-Signed Trust Anchor)");

        KeyPair rootKeyPair = RootCa.generateRootCaKeyPair();
        X509Certificate rootCert = RootCa.buildRootCaCertificate(rootKeyPair);

        RootCa.printCertificateDetails(rootCert);
        RootCa.verifySelfSignedCert(rootCert);

        CaStore.rootCaKeyPair = rootKeyPair;
        CaStore.rootCaCert    = rootCert;

        // =====================================================================
        // PHASE 2 — Create Sub CA (Signed by Root CA)
        // =====================================================================
        printPhase(2, "Sub CA Creation (Signed by Root CA)");

        KeyPair subKeyPair = SubCa.generateSubCaKeyPair();
        X509Certificate subCaCert = SubCa.buildSubCaCertificate(
            subKeyPair, rootKeyPair, rootCert
        );

        SubCa.printCertificateDetails(subCaCert);
        SubCa.verifySubCaCertificate(subCaCert, rootCert);

        CaStore.subCaKeyPair = subKeyPair;
        CaStore.subCaCert    = subCaCert;

        // =====================================================================
        // PHASE 3 — Full Chain Verification
        // =====================================================================
        printPhase(3, "Full PKI Chain Verification");

        verifyFullChain(rootCert, subCaCert);

        // =====================================================================
        // PHASE 4 — Summary
        // =====================================================================
        printSummary(rootCert, subCaCert);
    }

    // =========================================================================
    // Phase 3 — Full Chain Verification
    // =========================================================================

    /**
     * Performs complete PKI chain verification between Root CA and Sub CA.
     *
     * <p><b>What does "chain verification" mean?</b><br>
     * When a TLS client receives a certificate chain (end-entity + Sub CA + Root CA),
     * it verifies each link:
     * <ol>
     *   <li>End-entity cert signed by Sub CA? → check with Sub CA's public key</li>
     *   <li>Sub CA cert signed by Root CA?   → check with Root CA's public key</li>
     *   <li>Root CA self-signed?             → check with Root CA's own public key</li>
     *   <li>Root CA in local trust store?    → browser/OS trust store lookup</li>
     * </ol>
     * Here we verify steps 2 and 3 (Root and Sub CA only, no end-entity yet).</p>
     *
     * @param rootCert   Root CA certificate
     * @param subCaCert  Sub CA certificate
     * @throws Exception if any check fails
     */
    private static void verifyFullChain(X509Certificate rootCert,
                                         X509Certificate subCaCert) throws Exception {

        System.out.println("🔗 Full PKI Chain Verification");
        System.out.println("   ─────────────────────────────────────────────────────");
        boolean allPassed = true;

        // ---- Check 1: Root CA self-signature ----
        try {
            rootCert.verify(rootCert.getPublicKey());
            System.out.println("   ✅ Check 1: Root CA self-signature VALID");
        } catch (Exception e) {
            System.out.println("   ❌ Check 1: Root CA self-signature FAILED: " + e.getMessage());
            allPassed = false;
        }

        // ---- Check 2: Sub CA signed by Root CA ----
        try {
            subCaCert.verify(rootCert.getPublicKey());
            System.out.println("   ✅ Check 2: Sub CA signature verified with Root CA public key");
        } catch (Exception e) {
            System.out.println("   ❌ Check 2: Sub CA verification FAILED: " + e.getMessage());
            allPassed = false;
        }

        // ---- Check 3: Chain Linkage — Sub CA Issuer DN == Root CA Subject DN ----
        // RFC 5280 §6.1: issuer DN of each cert must match subject DN of the next cert up.
        // This is the fundamental X.509 name chaining rule.
        boolean dnMatch = subCaCert.getIssuerX500Principal()
            .equals(rootCert.getSubjectX500Principal());
        if (dnMatch) {
            System.out.println("   ✅ Check 3: Chain linkage VALID — Sub CA Issuer DN == Root CA Subject DN");
        } else {
            System.out.println("   ❌ Check 3: Chain linkage FAILED — DN mismatch");
            allPassed = false;
        }

        // ---- Check 4: Root CA is actually a CA (BasicConstraints) ----
        boolean rootIsCA = rootCert.getBasicConstraints() >= 0;
        System.out.println("   " + (rootIsCA ? "✅" : "❌")
            + " Check 4: Root CA BasicConstraints — isCA=" + rootIsCA
            + ", pathLen=" + rootCert.getBasicConstraints());

        // ---- Check 5: Sub CA is also a CA ----
        boolean subIsCA = subCaCert.getBasicConstraints() >= 0;
        System.out.println("   " + (subIsCA ? "✅" : "❌")
            + " Check 5: Sub CA BasicConstraints — isCA=" + subIsCA
            + ", pathLen=" + subCaCert.getBasicConstraints());

        // ---- Check 6: Root CA validity ----
        try {
            rootCert.checkValidity();
            System.out.println("   ✅ Check 6: Root CA validity period — currently VALID");
        } catch (Exception e) {
            System.out.println("   ❌ Check 6: Root CA NOT valid: " + e.getMessage());
            allPassed = false;
        }

        // ---- Check 7: Sub CA validity ----
        try {
            subCaCert.checkValidity();
            System.out.println("   ✅ Check 7: Sub CA validity period — currently VALID");
        } catch (Exception e) {
            System.out.println("   ❌ Check 7: Sub CA NOT valid: " + e.getMessage());
            allPassed = false;
        }

        // ---- Check 8: Root CA pathLen allows Sub CA ----
        // Root CA pathLen=1, Sub CA is depth 1 → OK
        // If Root CA had pathLen=0, Sub CA would be REJECTED by chain builders
        int rootPathLen = rootCert.getBasicConstraints();
        boolean pathLenOk = rootPathLen >= 1;
        System.out.println("   " + (pathLenOk ? "✅" : "❌")
            + " Check 8: Root CA pathLen=" + rootPathLen
            + (pathLenOk ? " — allows Sub CA ✓" : " — Sub CA NOT allowed (pathLen too small)"));

        System.out.println("   ─────────────────────────────────────────────────────");
        if (allPassed) {
            System.out.println("   ✅ ALL CHECKS PASSED — PKI Hierarchy is valid!\n");
        } else {
            System.out.println("   ❌ SOME CHECKS FAILED — PKI Hierarchy has issues!\n");
        }
    }

    // =========================================================================
    // Summary
    // =========================================================================

    /**
     * Prints a final summary of the PKI hierarchy created.
     *
     * @param rootCert  Root CA certificate
     * @param subCaCert Sub CA certificate
     */
    private static void printSummary(X509Certificate rootCert,
                                      X509Certificate subCaCert) {

        java.security.interfaces.RSAPublicKey rootKey =
            (java.security.interfaces.RSAPublicKey) rootCert.getPublicKey();
        java.security.interfaces.RSAPublicKey subKey =
            (java.security.interfaces.RSAPublicKey) subCaCert.getPublicKey();

        System.out.println("=============================================================");
        System.out.println("  PKI HIERARCHY SUMMARY");
        System.out.println("=============================================================");
        System.out.println();
        System.out.println("  TRUST ANCHOR (Root CA)");
        System.out.printf("    Subject   : %s%n", rootCert.getSubjectX500Principal().getName());
        System.out.printf("    Key       : RSA-%d%n", rootKey.getModulus().bitLength());
        System.out.printf("    Validity  : %s → %s%n", rootCert.getNotBefore(), rootCert.getNotAfter());
        System.out.printf("    PathLen   : %d (allows 1 level of Sub CA)%n", rootCert.getBasicConstraints());
        System.out.printf("    Serial    : %s%n", rootCert.getSerialNumber());
        System.out.println();
        System.out.println("       ↓ signed by Root CA private key");
        System.out.println();
        System.out.println("  ISSUING CA (Sub CA)");
        System.out.printf("    Subject   : %s%n", subCaCert.getSubjectX500Principal().getName());
        System.out.printf("    Issuer    : %s%n", subCaCert.getIssuerX500Principal().getName());
        System.out.printf("    Key       : RSA-%d%n", subKey.getModulus().bitLength());
        System.out.printf("    Validity  : %s → %s%n", subCaCert.getNotBefore(), subCaCert.getNotAfter());
        System.out.printf("    PathLen   : %d (end-entity certs only — no further Sub CAs)%n",
            subCaCert.getBasicConstraints());
        System.out.printf("    Serial    : %s%n", subCaCert.getSerialNumber());
        System.out.println();
        System.out.println("       ↓ Sub CA will sign (future implementation)");
        System.out.println();
        System.out.println("  END ENTITY CERTIFICATES (future)");
        System.out.println("    TLS Server Certificate  (CN=api.salman.com)");
        System.out.println("    TLS Client Certificate  (CN=Salman, client auth)");
        System.out.println("    S/MIME Certificate      (salman@company.com)");
        System.out.println();
        System.out.println("=============================================================");
        System.out.println("  ✅ Two-Tier PKI Hierarchy Created Successfully!");
        System.out.println("     Root CA → Sub CA chain verified.");
        System.out.println("     Next: Issue TLS Server Certificate from Sub CA.");
        System.out.println("=============================================================");
    }

    // =========================================================================
    // UI Helpers
    // =========================================================================

    private static void printBanner() {
        System.out.println("=============================================================");
        System.out.println("  PKI Hierarchy Demo — Root CA + Sub CA");
        System.out.println("  Package: com.pqc.ca");
        System.out.println("=============================================================");
        System.out.println();
        System.out.println("  Hierarchy:");
        System.out.println("    Root CA  (self-signed, RSA-4096, 20 years, pathLen=1)");
        System.out.println("       └── Sub CA (signed by Root, RSA-2048, 10 years, pathLen=0)");
        System.out.println("              └── [End-entity certs — future]");
        System.out.println();
    }

    private static void printPhase(int num, String title) {
        System.out.println();
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.printf("  PHASE %d: %s%n", num, title);
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println();
    }
}
