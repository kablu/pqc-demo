package com.pqc.ca.tls;

import com.pqc.ca.CaStore;
import com.pqc.ca.RootCa;
import com.pqc.ca.SubCa;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * Full TLS Server Certificate Pipeline — Step01 through certificate issuance.
 *
 * <pre>
 * Phase 1: CA Hierarchy   — Root CA + Sub CA
 * Phase 2: Key Pair       — Step01_ServerKeyPairGeneration
 * Phase 3: CSR            — Step02_CsrGeneration
 * Phase 4: Cert Issuance  — Sub CA signs server certificate
 * Phase 5: Verification   — chain validation + field inspection
 * </pre>
 *
 * Run: {@code .\gradlew.bat tls-pipeline}
 */
public class TlsPipelineRunner {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        log("=================================================================");
        log("  TLS Server Certificate Pipeline — End-to-End Test");
        log("=================================================================\n");

        // =====================================================================
        // Phase 1: Build CA Hierarchy (Root CA → Sub CA)
        // =====================================================================
        log("━━━ Phase 1: CA Hierarchy ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        CaStore.rootCaKeyPair = RootCa.generateRootCaKeyPair();
        log("[CA] Root CA RSA-4096 key pair generated");

        CaStore.rootCaCert = RootCa.buildRootCaCertificate(CaStore.rootCaKeyPair);
        log("[CA] Root CA self-signed certificate built");
        log("[CA] Root CA Subject : " + CaStore.rootCaCert.getSubjectX500Principal().getName());

        CaStore.subCaKeyPair = SubCa.generateSubCaKeyPair();
        log("[CA] Sub CA RSA-2048 key pair generated");

        CaStore.subCaCert = SubCa.buildSubCaCertificate(
            CaStore.subCaKeyPair, CaStore.rootCaKeyPair, CaStore.rootCaCert);
        log("[CA] Sub CA certificate signed by Root CA");
        log("[CA] Sub CA Subject  : " + CaStore.subCaCert.getSubjectX500Principal().getName());

        // =====================================================================
        // Phase 2: Server Key Pair (Step01)
        // =====================================================================
        log("\n━━━ Phase 2: Server Key Pair (Step01) ━━━━━━━━━━━━━━━━━━━━━━━━━");

        TlsCertStore.serverKeyPair = Step01_ServerKeyPairGeneration.generateServerKeyPair();
        log("[KP] RSA-2048 server key pair generated");
        log("[KP] Algorithm : " + TlsCertStore.serverKeyPair.getPublic().getAlgorithm());

        // =====================================================================
        // Phase 3: CSR Generation (Step02)
        // =====================================================================
        log("\n━━━ Phase 3: CSR Generation (Step02) ━━━━━━━━━━━━━━━━━━━━━━━━━");

        PKCS10CertificationRequest csr = Step02_CsrGeneration.generateCsr();
        log("[CSR] PKCS#10 CSR built and signed");
        log("[CSR] Subject  : " + csr.getSubject());

        // =====================================================================
        // Phase 4: Certificate Issuance by Sub CA
        // =====================================================================
        log("\n━━━ Phase 4: Certificate Issuance by Sub CA ━━━━━━━━━━━━━━━━━━");

        // 4A: Verify CSR signature (Proof of Possession)
        log("[ISSUE] 4A: Verifying CSR signature (proof of possession)...");
        boolean csrSigValid = csr.isSignatureValid(
            new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(TlsCertStore.serverKeyPair.getPublic())
        );
        if (!csrSigValid) {
            throw new IllegalStateException("CSR signature INVALID — rejecting request");
        }
        log("[ISSUE] 4A: CSR signature VALID ✔");

        // 4B: Extract subject and public key from CSR
        log("[ISSUE] 4B: Extracting subject DN and public key from CSR...");
        org.bouncycastle.asn1.x500.X500Name subject = csr.getSubject();
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki = csr.getSubjectPublicKeyInfo();
        log("[ISSUE] 4B: Subject = " + subject);

        // 4C: Build certificate
        log("[ISSUE] 4C: Building X.509v3 TLS server certificate...");

        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter  = Date.from(now.plus(365, ChronoUnit.DAYS)); // 1 year validity

        org.bouncycastle.asn1.x500.X500Name issuerDn = new org.bouncycastle.asn1.x500.X500Name(
            CaStore.subCaCert.getSubjectX500Principal().getName()
        );

        BigInteger serial = new BigInteger(64, new java.security.SecureRandom());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuerDn, serial, notBefore, notAfter, subject,
            TlsCertStore.serverKeyPair.getPublic()
        );

        // Extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // SKID
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(TlsCertStore.serverKeyPair.getPublic()));

        // AKID — links to Sub CA
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
            extUtils.createAuthorityKeyIdentifier(CaStore.subCaCert));

        // BasicConstraints isCA=false
        certBuilder.addExtension(Extension.basicConstraints, true,
            new BasicConstraints(false));

        // KeyUsage
        certBuilder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // ExtendedKeyUsage — TLS server auth
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        // SAN — copy from CSR
        org.bouncycastle.asn1.pkcs.Attribute[] attrs = csr.getAttributes(
            org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs.length > 0) {
            Extensions csrExts = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));
            Extension sanExt = csrExts.getExtension(Extension.subjectAlternativeName);
            if (sanExt != null) {
                // Decode OCTET STRING → raw bytes → ASN1Primitive → GeneralNames
                // Avoids both DLSequence and corrupted-stream parse errors
                byte[] sanBytes = sanExt.getExtnValue().getOctets();
                org.bouncycastle.asn1.x509.GeneralNames generalNames =
                    org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                        org.bouncycastle.asn1.ASN1Primitive.fromByteArray(sanBytes));
                certBuilder.addExtension(Extension.subjectAlternativeName,
                    sanExt.isCritical(), generalNames);
                log("[ISSUE] 4C: SAN copied from CSR");
            }
        }

        log("[ISSUE] 4C: Extensions added: SKID, AKID, BasicConstraints, KeyUsage, EKU, SAN");

        // 4D: Sign with Sub CA private key
        log("[ISSUE] 4D: Signing certificate with Sub CA private key (SHA384withRSA)...");
        ContentSigner subCaSigner = new JcaContentSignerBuilder("SHA384withRSA")
            .setProvider("BC")
            .build(CaStore.subCaKeyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(subCaSigner);
        X509Certificate serverCert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);

        TlsCertStore.serverCert = serverCert;
        log("[ISSUE] 4D: Certificate signed successfully ✔");

        // PEM encode
        byte[] derBytes = serverCert.getEncoded();
        String certPem = "-----BEGIN CERTIFICATE-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                    .encodeToString(derBytes)
            + "\n-----END CERTIFICATE-----\n";
        TlsCertStore.serverCertPem = certPem;

        // =====================================================================
        // Phase 5: Verification
        // =====================================================================
        log("\n━━━ Phase 5: Verification ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // 5A: Signature verification — Sub CA signed this cert?
        log("[VERIFY] 5A: Verifying certificate signature with Sub CA public key...");
        serverCert.verify(CaStore.subCaCert.getPublicKey(), Security.getProvider("BC"));
        log("[VERIFY] 5A: Signature VALID ✔");

        // 5B: Print certificate fields
        log("[VERIFY] 5B: Certificate details:");
        log("         Serial       : 0x" + serverCert.getSerialNumber().toString(16));
        log("         Subject      : " + serverCert.getSubjectX500Principal().getName());
        log("         Issuer       : " + serverCert.getIssuerX500Principal().getName());
        log("         Not Before   : " + serverCert.getNotBefore());
        log("         Not After    : " + serverCert.getNotAfter());
        log("         Sig Alg      : " + serverCert.getSigAlgName());
        log("         Key Alg      : " + serverCert.getPublicKey().getAlgorithm());
        log("         isCA         : false (BasicConstraints)");

        // 5C: Chain verification Root CA → Sub CA → Server
        log("[VERIFY] 5C: Chain: Root CA → Sub CA → Server cert");
        CaStore.subCaCert.verify(CaStore.rootCaCert.getPublicKey(), Security.getProvider("BC"));
        log("[VERIFY] 5C: Sub CA ← Root CA signature VALID ✔");
        serverCert.verify(CaStore.subCaCert.getPublicKey(), Security.getProvider("BC"));
        log("[VERIFY] 5C: Server ← Sub CA signature VALID ✔");
        log("[VERIFY] 5C: Full chain VALID ✔");

        // 5D: Print PEM
        log("\n[PEM] TLS Server Certificate:");
        System.out.println(certPem);

        log("=================================================================");
        log("  ✔ CERTIFICATE SUCCESSFULLY GENERATED");
        log("  Subject  : " + serverCert.getSubjectX500Principal().getName());
        log("  Issuer   : " + serverCert.getIssuerX500Principal().getName());
        log("  Valid    : " + serverCert.getNotBefore() + " → " + serverCert.getNotAfter());
        log("=================================================================");
    }

    static void log(String msg) {
        System.out.println(msg);
    }
}
