package com.pqc;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * =========================================================================
 * Task 07 — CMS Signed Data (PKCS#7 / RFC 5652)
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * CMS (Cryptographic Message Syntax) — formerly PKCS#7 — ek standard format
 * hai digitally signed data wrap karne ke liye. PKI mein yeh bahut jagah use
 * hota hai: SCEP (cert enrollment), S/MIME (email), signed JARs,
 * CMP responses, code signing, and EST protocol responses.
 * </p>
 *
 * <h2>CMS Kahan Use Hota Hai RA System Mein?</h2>
 * <ul>
 *   <li><b>SCEP Protocol</b> — enrollment messages are PKCS#7 SignedData</li>
 *   <li><b>CMP Protocol</b> — CA responses wrapped in CMS structures</li>
 *   <li><b>EST</b> — certificate responses in PKCS#7 cmsSequence format</li>
 *   <li><b>Audit Log Signing</b> — CMS-sign audit events for non-repudiation</li>
 * </ul>
 *
 * <h2>CMS SignedData Structure (RFC 5652)</h2>
 * <pre>
 * SignedData {
 *   version         = 1
 *   digestAlgorithms= [SHA-384]
 *   encapContentInfo= {
 *     eContentType = id-data (1.2.840.113549.1.7.1)
 *     eContent     = [the actual signed data bytes]
 *   }
 *   certificates    = [signer's cert + chain]
 *   signerInfos     = [{
 *     version           = 1
 *     sid               = issuerAndSerialNumber of signer cert
 *     digestAlgorithm   = SHA-384
 *     signedAttrs       = {contentType, signingTime, messageDigest}
 *     signatureAlgorithm= SHA384withRSA
 *     signature         = [RSA signature over signedAttrs hash]
 *   }]
 * }
 * </pre>
 *
 * <h2>Detached vs Attached Signatures</h2>
 * <pre>
 * Attached (encapsulated): data INSIDE the CMS structure — self-contained
 * Detached               : data NOT in CMS — signer and data stored separately
 *                          Used when: data is large, or already stored elsewhere
 *                          Verification: need both CMS + original data
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task07_CmsSignedData</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class Task07_CmsSignedData {

    /**
     * Entry point — signs data and then verifies the CMS SignedData.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if CMS creation or verification fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 07 — CMS Signed Data (PKCS#7)");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        if (CertificateStore.entityCert == null) {
            Task04_IssueCertFromCsr.main(new String[]{});
        }

        // Data to sign — simulating a certificate request or audit event payload
        String payload = "CERTIFICATE_APPROVED: device-001.company.com | " +
                         "Serial: abc123 | RA Officer: admin | Time: 2026-03-15T06:00:00Z";

        System.out.println("📝 Data to sign: " + payload + "\n");

        // Part A: Create attached CMS SignedData (data inside the CMS structure)
        System.out.println("── Part A: Attached CMS Signature ──────────────────────────\n");
        CMSSignedData attachedSig = createAttachedSignedData(payload.getBytes(StandardCharsets.UTF_8));
        printCmsDetails(attachedSig, "Attached");
        verifyCmsSignature(attachedSig, null, CertificateStore.entityCert);

        // Part B: Create detached CMS SignedData (data NOT inside CMS)
        System.out.println("── Part B: Detached CMS Signature ───────────────────────────\n");
        byte[] originalData = payload.getBytes(StandardCharsets.UTF_8);
        CMSSignedData detachedSig = createDetachedSignedData(originalData);
        printCmsDetails(detachedSig, "Detached");
        verifyCmsSignature(detachedSig, originalData, CertificateStore.entityCert);

        System.out.println("✅ Task 07 Complete — CMS SignedData created and verified!");
        System.out.println("   Next Step → Task08_Pkcs12KeyStore.java");
    }

    // =========================================================================
    // Part A — Attached Signature (Data Inside CMS)
    // =========================================================================

    /**
     * Creates a CMS SignedData with the content ATTACHED (encapsulated inside).
     *
     * <p><b>WHY attached?</b><br>
     * When the recipient only receives the CMS file (no separate data file),
     * attached signature is used. The verifier extracts data from the CMS.
     * Use case: signed email body (S/MIME), signed SCEP message.</p>
     *
     * <p><b>Signed Attributes — WHY?</b><br>
     * CMS adds "signed attributes" automatically:
     * <ul>
     *   <li>contentType — what type of content is signed</li>
     *   <li>messageDigest — SHA hash of the content</li>
     *   <li>signingTime — timestamp of signing</li>
     * </ul>
     * The RSA signature signs these attributes (not the raw content directly),
     * which allows adding authenticated metadata.</p>
     *
     * @param data the bytes to sign and encapsulate
     * @return the {@link CMSSignedData} with content attached
     * @throws Exception if signing fails
     */
    public static CMSSignedData createAttachedSignedData(byte[] data) throws Exception {
        System.out.println("✍️  Creating attached CMS SignedData...");
        CMSSignedData signedData = buildSignedData(data, true);
        System.out.printf("✔ Attached CMS SignedData created (%d bytes)%n%n",
            signedData.getEncoded().length);
        return signedData;
    }

    // =========================================================================
    // Part B — Detached Signature (Data NOT in CMS)
    // =========================================================================

    /**
     * Creates a CMS SignedData with the content DETACHED (NOT inside CMS).
     *
     * <p><b>WHY detached?</b><br>
     * Detached signatures are used when:
     * <ul>
     *   <li>Data is very large (binary, video) — don't duplicate it in CMS</li>
     *   <li>Data is stored separately in a database (audit log, cert storage)</li>
     *   <li>You want to add signature to existing data without modifying it</li>
     * </ul>
     * Use case: signed code (JAR signing, APK), signed database audit records,
     * RFC 3161 timestamp tokens.</p>
     *
     * @param data the bytes to sign (NOT included in the returned CMS)
     * @return the {@link CMSSignedData} without content (detached)
     * @throws Exception if signing fails
     */
    public static CMSSignedData createDetachedSignedData(byte[] data) throws Exception {
        System.out.println("✍️  Creating detached CMS SignedData...");
        // generate(data, encapsulate=false) — signature still covers data, but bytes NOT stored in CMS
        CMSSignedData detachedSig = buildSignedData(data, false);
        System.out.printf("✔ Detached CMS SignedData created (%d bytes — smaller than attached)%n%n",
            detachedSig.getEncoded().length);
        return detachedSig;
    }

    /**
     * Shared CMS SignedData builder — used by both attached and detached variants.
     *
     * <p><b>CMSSignedDataGenerator steps:</b>
     * <ol>
     *   <li>Add signer info: which key+cert is signing</li>
     *   <li>Add certificates: chain so verifier can validate signer's cert</li>
     *   <li>generate(data, encapsulate): true=attached, false=detached</li>
     * </ol>
     * </p>
     *
     * @param data        the bytes to sign
     * @param encapsulate {@code true} to embed data in the CMS (attached),
     *                    {@code false} to produce a detached signature
     * @return the assembled {@link CMSSignedData}
     * @throws Exception if signing fails
     */
    private static CMSSignedData buildSignedData(byte[] data, boolean encapsulate) throws Exception {
        // Create the generator that will assemble the SignedData structure
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        // ---- Add Signer Info ----
        // JcaSignerInfoGeneratorBuilder: builds a SignerInfo from key + cert
        // digestProvider: computes message digest (SHA-384) of content
        // SHA384withRSA: the overall signature algorithm (hash + encryption)
        gen.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
            ).build(
                // ContentSigner: holds the private key and algorithm for signing
                new JcaContentSignerBuilder("SHA384withRSA")
                    .setProvider("BC")
                    // WHY entity private key here? We're signing as the entity (device)
                    // In RA audit signing, you'd use the RA officer's signing key
                    .build(CertificateStore.entityKeyPair.getPrivate()),
                // Signer's certificate — identifies who created the signature
                CertificateStore.entityCert
            )
        );

        // ---- Add Certificate Chain ----
        // Including certs allows verifiers to build the chain without external lookups
        // JcaCertStore wraps Java X509Certificate list into BC's certificate store format
        gen.addCertificates(new JcaCertStore(List.of(
            CertificateStore.entityCert,  // signer's cert
            CertificateStore.caCert       // issuing CA cert (chain)
        )));

        // CMSProcessableByteArray: wraps raw bytes as CMS processable content
        return gen.generate(new CMSProcessableByteArray(data), encapsulate);
    }

    // =========================================================================
    // Part C — Verify CMS Signature
    // =========================================================================

    /**
     * Verifies all signers in a CMS SignedData structure.
     *
     * <p><b>Verification steps:</b>
     * <ol>
     *   <li>Get all SignerInfo blocks from the CMS</li>
     *   <li>For each signer: find their certificate</li>
     *   <li>Verify the signature using the signer's public key</li>
     *   <li>For detached: re-provide the original data for hash computation</li>
     * </ol>
     * </p>
     *
     * @param signedData   the CMS SignedData to verify
     * @param originalData null for attached, original bytes for detached
     * @param signerCert   the expected signer certificate
     * @throws Exception if verification fails
     */
    public static void verifyCmsSignature(CMSSignedData signedData,
                                           byte[] originalData,
                                           X509Certificate signerCert) throws Exception {
        System.out.println("🔍 Verifying CMS Signature...");

        // If detached, we need to re-attach the original data for hash computation
        CMSSignedData toVerify = signedData;
        if (originalData != null && signedData.getSignedContent() == null) {
            // Reconstruct with original data so the digest can be computed for verification
            toVerify = new CMSSignedData(
                new CMSProcessableByteArray(originalData),
                signedData.toASN1Structure()
            );
        }

        // getSignerInfos() = all signers in this CMS (there can be multiple)
        SignerInformationStore signers = toVerify.getSignerInfos();
        Collection<SignerInformation> signerList = signers.getSigners();

        System.out.println("   Number of signers: " + signerList.size());

        for (SignerInformation signer : signerList) {
            // JcaSimpleSignerInfoVerifierBuilder: verify signer's signature using cert's public key
            boolean valid = signer.verify(
                new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC")
                    .build(signerCert) // verify against expected signer's cert
            );

            if (valid) {
                System.out.println("   ✅ Signer [" + signerCert.getSubjectX500Principal().getName() + "] — SIGNATURE VALID!");
                System.out.println("   Digest Algorithm : " + signer.getDigestAlgOID());
                System.out.println("   Sig Algorithm    : " + signer.getEncryptionAlgOID());
            } else {
                System.out.println("   ❌ Signature INVALID for signer!");
            }
        }
        System.out.println();
    }

    /**
     * Prints the structural details of a CMS SignedData.
     *
     * @param signedData the CMS structure to inspect
     * @param type       "Attached" or "Detached" label for output
     * @throws Exception if encoding fails
     */
    public static void printCmsDetails(CMSSignedData signedData, String type) throws Exception {
        System.out.println("📋 CMS SignedData Details (" + type + "):");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");
        System.out.printf( "   │ Total Size        : %d bytes%n", signedData.getEncoded().length);
        System.out.printf( "   │ Content Type      : %s%n", signedData.getSignedContentTypeOID());
        System.out.printf( "   │ Signer Count      : %d%n", signedData.getSignerInfos().size());
        System.out.printf( "   │ Cert Count        : %d%n", signedData.getCertificates().getMatches(null).size());
        System.out.printf( "   │ Content Present   : %s%n",
            signedData.getSignedContent() != null ? "YES (attached)" : "NO (detached)");
        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }
}
