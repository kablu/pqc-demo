package com.pqc.ca.tls;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;

/**
 * =========================================================================
 * Step 02 — CSR Generation (Maximum Granular Attributes)
 * =========================================================================
 *
 * <p>Ek PKCS#10 Certificate Signing Request (CSR) generate karta hai
 * TLS server ke liye, maximum granular DN attributes aur X.509v3 extensions
 * ke saath. CSR Sub CA ko bheja jaata hai (Step03).</p>
 *
 * <h2>Sub-steps:</h2>
 * <pre>
 *  2A — Key pair load / generate
 *  2B — X500Name (DN) build with 10 attributes
 *  2C — SAN extension (3 DNS + 1 IP)
 *  2D — KeyUsage extension
 *  2E — ExtendedKeyUsage (TLS Web Server Auth)
 *  2F — BasicConstraints (isCA=false)
 *  2G — SubjectKeyIdentifier
 *  2H — Build + sign PKCS#10 CSR
 *  2I — Save cert/server.csr.pem
 *  2J — Store in TlsCertStore
 * </pre>
 *
 * Run: {@code .\gradlew.bat run -PmainClass=com.pqc.ca.tls.Step02_CsrGeneration}
 */
public class Step02_CsrGeneration {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        log("INIT    ", "============================================================");
        log("INIT    ", "  Step 02 — CSR Generation with Maximum Granular Attributes");
        log("INIT    ", "============================================================");

        generateCsr();

        log("DONE    ", "Step 02 Complete — CSR saved to cert/server.csr.pem");
        log("DONE    ", "Next Step → Step03_CsrSubmissionToSubCa.java");
    }

    public static PKCS10CertificationRequest generateCsr() throws Exception {

        // =====================================================================
        // Sub-step 2A: Load server key pair from TlsCertStore (or generate)
        // =====================================================================
        log("2A      ", "--- Sub-step 2A: Load Server Key Pair ---");

        KeyPair keyPair = TlsCertStore.serverKeyPair;
        if (keyPair == null) {
            log("2A      ", "TlsCertStore.serverKeyPair is null — running Step01 first...");
            keyPair = Step01_ServerKeyPairGeneration.generateServerKeyPair();
            TlsCertStore.serverKeyPair = keyPair;
            log("2A      ", "Step01 completed inline — key pair available");
        } else {
            log("2A      ", "Key pair loaded from TlsCertStore.serverKeyPair");
        }
        log("2A      ", "Public key algorithm : " + keyPair.getPublic().getAlgorithm());
        log("2A      ", "Public key format    : " + keyPair.getPublic().getFormat());

        // =====================================================================
        // Sub-step 2B: Build X500Name (Distinguished Name) — 10 attributes
        // =====================================================================
        log("2B      ", "--- Sub-step 2B: Build X500Name (DN) with 10 attributes ---");

        /*
         * X.500 DN attribute order (RFC 5280 §4.1.2.6):
         * Most specific → most general when reading left-to-right in string form.
         * BouncyCastle X500NameBuilder builds in reverse — last added = most specific.
         *
         * BCStyle OID reference:
         *   CN             = 2.5.4.3   — Common Name
         *   O              = 2.5.4.10  — Organization
         *   OU             = 2.5.4.11  — Organizational Unit
         *   L              = 2.5.4.7   — Locality (City)
         *   ST             = 2.5.4.8   — State/Province
         *   C              = 2.5.4.6   — Country (ISO 3166-1 alpha-2)
         *   STREET         = 2.5.4.9   — Street Address
         *   POSTAL_CODE    = 2.5.4.17  — Postal/ZIP Code
         *   SERIALNUMBER   = 2.5.4.5   — Device/Server Serial Number
         *   BUSINESS_CATEGORY = 2.5.4.15 — Business Category
         */
        X500NameBuilder dnBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        // Country — MUST be ISO 3166-1 alpha-2, exactly 2 chars, PRINTABLESTRING
        dnBuilder.addRDN(BCStyle.C, "IN");
        log("2B      ", "  C  (Country)            = IN");

        // State or Province — full name, no abbreviation required
        dnBuilder.addRDN(BCStyle.ST, "Maharashtra");
        log("2B      ", "  ST (State)               = Maharashtra");

        // Locality — city name
        dnBuilder.addRDN(BCStyle.L, "Mumbai");
        log("2B      ", "  L  (Locality)            = Mumbai");

        // Street Address — building/floor/road
        dnBuilder.addRDN(BCStyle.STREET, "123 Tech Park, Andheri East");
        log("2B      ", "  STREET                   = 123 Tech Park, Andheri East");

        // Postal Code — ZIP/PIN code
        dnBuilder.addRDN(BCStyle.POSTAL_CODE, "400069");
        log("2B      ", "  PostalCode               = 400069");

        // Organization — legal entity name
        dnBuilder.addRDN(BCStyle.O, "Salman Technologies Pvt Ltd");
        log("2B      ", "  O  (Organization)        = Salman Technologies Pvt Ltd");

        // Organizational Unit — department/team
        dnBuilder.addRDN(BCStyle.OU, "IT Infrastructure");
        log("2B      ", "  OU (Org Unit)            = IT Infrastructure");

        // Business Category — describes the nature of business (OID 2.5.4.15)
        dnBuilder.addRDN(BCStyle.BUSINESS_CATEGORY, "Internet Service Provider");
        log("2B      ", "  businessCategory         = Internet Service Provider");

        // Serial Number — device/server identifier (NOT the certificate serial)
        // Used in EV certificates to uniquely identify the server
        dnBuilder.addRDN(BCStyle.SERIALNUMBER, "SRV-2026-001");
        log("2B      ", "  serialNumber (device)    = SRV-2026-001");

        // Common Name — MUST match the primary hostname (or wildcard)
        // Browsers check CN only if SAN is absent; SAN always takes precedence
        dnBuilder.addRDN(BCStyle.CN, "api.salman.com");
        log("2B      ", "  CN (Common Name)         = api.salman.com");

        X500Name subject = dnBuilder.build();
        log("2B      ", "X500Name built: " + subject);

        // =====================================================================
        // Sub-step 2C: SAN (Subject Alternative Names) — 3 DNS + 1 IP
        // =====================================================================
        log("2C      ", "--- Sub-step 2C: Subject Alternative Names (SAN) ---");

        /*
         * SAN is the authoritative source for hostnames in TLS (RFC 2818 §3.1).
         * All modern clients (Chrome, Firefox, Java, curl) ignore CN if SAN is present.
         * Must include ALL hostnames the server will use.
         *
         * GeneralName types:
         *   dNSName    [2] — hostname (wildcard allowed: *.salman.com)
         *   iPAddress  [7] — 4 bytes for IPv4, 16 bytes for IPv6 (raw bytes, not string)
         */
        GeneralName[] sanEntries = new GeneralName[] {
            new GeneralName(GeneralName.dNSName, "api.salman.com"),
            new GeneralName(GeneralName.dNSName, "www.salman.com"),
            new GeneralName(GeneralName.dNSName, "admin.salman.com"),
            new GeneralName(GeneralName.iPAddress, "192.168.1.100")
        };
        log("2C      ", "  SAN[0] dNSName   = api.salman.com");
        log("2C      ", "  SAN[1] dNSName   = www.salman.com");
        log("2C      ", "  SAN[2] dNSName   = admin.salman.com");
        log("2C      ", "  SAN[3] iPAddress = 192.168.1.100");

        GeneralNames subjectAltNames = new GeneralNames(sanEntries);

        // =====================================================================
        // Sub-step 2D: KeyUsage extension
        // =====================================================================
        log("2D      ", "--- Sub-step 2D: KeyUsage Extension ---");

        /*
         * KeyUsage bits (RFC 5280 §4.2.1.3):
         *   digitalSignature  — sign TLS handshake (required for RSA/ECDSA TLS)
         *   keyEncipherment   — encrypt the pre-master secret (RSA key exchange)
         *
         * NOT set for TLS server:
         *   keyCertSign, cRLSign — only for CAs
         *   nonRepudiation      — for document signing
         *   dataEncipherment    — for S/MIME, not TLS
         *
         * Critical = true per RFC 5280 §4.2.1.3 when KeyUsage is present.
         */
        KeyUsage keyUsage = new KeyUsage(
            KeyUsage.digitalSignature | KeyUsage.keyEncipherment
        );
        log("2D      ", "  KeyUsage = digitalSignature | keyEncipherment  (critical=true)");

        // =====================================================================
        // Sub-step 2E: ExtendedKeyUsage — TLS Web Server Authentication
        // =====================================================================
        log("2E      ", "--- Sub-step 2E: ExtendedKeyUsage Extension ---");

        /*
         * EKU OIDs (RFC 5280 §4.2.1.12):
         *   id-kp-serverAuth  1.3.6.1.5.5.7.3.1 — TLS server authentication
         *   id-kp-clientAuth  1.3.6.1.5.5.7.3.2 — TLS client authentication
         *
         * TLS server certificate MUST have serverAuth EKU.
         * Browsers reject server certs without it since ~2020.
         */
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
            KeyPurposeId.id_kp_serverAuth
        );
        log("2E      ", "  EKU = id-kp-serverAuth (1.3.6.1.5.5.7.3.1)");

        // =====================================================================
        // Sub-step 2F: BasicConstraints — isCA=false
        // =====================================================================
        log("2F      ", "--- Sub-step 2F: BasicConstraints (isCA=false) ---");

        /*
         * BasicConstraints MUST be present and critical in CA certs.
         * For end-entity (leaf) certs: isCA=false, no pathLenConstraint.
         * Setting isCA=false explicitly prevents cert from being used as a CA
         * even if other constraints are misconfigured.
         */
        BasicConstraints basicConstraints = new BasicConstraints(false);
        log("2F      ", "  BasicConstraints isCA=false  (critical=true)");

        // =====================================================================
        // Sub-step 2G: SubjectKeyIdentifier
        // =====================================================================
        log("2G      ", "--- Sub-step 2G: SubjectKeyIdentifier (SKID) ---");

        /*
         * SKID = SHA-1 hash of the SubjectPublicKeyInfo bit string (RFC 5280 §4.2.1.2).
         * Used by CAs and clients to identify which public key this cert refers to.
         * Not critical. JcaX509ExtensionUtils computes the standard SHA-1 SKID.
         */
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier skid = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
        log("2G      ", "  SKID computed from SHA-1(SubjectPublicKeyInfo)");

        // =====================================================================
        // Sub-step 2H: Build Extensions + Sign PKCS#10 CSR
        // =====================================================================
        log("2H      ", "--- Sub-step 2H: Build PKCS#10 CSR and Sign ---");

        /*
         * PKCS#10 CSR structure (RFC 2986):
         *   CertificationRequestInfo {
         *     version    = 0 (v1)
         *     subject    = X500Name (DN)
         *     publicKey  = SubjectPublicKeyInfo
         *     attributes = [ ExtensionRequest { extensions... } ]
         *   }
         *   signatureAlgorithm = SHA256withRSA
         *   signature = sign(CertificationRequestInfo, privateKey)
         *
         * The CSR is signed with the server's PRIVATE KEY — this is "Proof of Possession":
         * proves the requestor holds the private key matching the public key in the CSR.
         * The Sub CA MUST verify this signature before issuing the certificate.
         */

        // Pack all extensions into an ExtensionsGenerator
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        extGen.addExtension(Extension.keyUsage,               true,  keyUsage);
        extGen.addExtension(Extension.extendedKeyUsage,       false, extendedKeyUsage);
        extGen.addExtension(Extension.basicConstraints,       true,  basicConstraints);
        extGen.addExtension(Extension.subjectKeyIdentifier,   false, skid);

        Extensions csrExtensions = extGen.generate();
        log("2H      ", "ExtensionsGenerator: 5 extensions packed");

        // Build the CSR using JCA-friendly builder
        JcaPKCS10CertificationRequestBuilder csrBuilder =
            new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        // Attach extensions as a PKCS#9 extensionRequest attribute
        csrBuilder.addAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
            csrExtensions
        );
        log("2H      ", "extensionRequest attribute added to CSR");

        // Sign the CSR with the server's private key — SHA256withRSA
        ContentSigner csrSigner = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
        log("2H      ", "CSR signer: SHA256withRSA with server private key");

        PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);
        log("2H      ", "PKCS#10 CSR built and signed successfully");

        // Encode to PEM
        byte[] derBytes = csr.getEncoded();
        String csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(derBytes)
            + "\n-----END CERTIFICATE REQUEST-----\n";

        log("2H      ", "CSR DER size : " + derBytes.length + " bytes");
        log("2H      ", "CSR PEM size : " + csrPem.length() + " chars");

        // =====================================================================
        // Sub-step 2I: Save cert/server.csr.pem
        // =====================================================================
        log("2I      ", "--- Sub-step 2I: Save cert/server.csr.pem ---");

        saveCsrPem(csrPem);
        log("2I      ", "Saved: cert/server.csr.pem");

        // =====================================================================
        // Sub-step 2J: Store in TlsCertStore
        // =====================================================================
        log("2J      ", "--- Sub-step 2J: Store in TlsCertStore ---");

        TlsCertStore.serverCsr  = csr;
        TlsCertStore.csrPem     = csrPem;
        log("2J      ", "TlsCertStore.serverCsr  = <PKCS10CertificationRequest>");
        log("2J      ", "TlsCertStore.csrPem     = <PEM string, " + csrPem.length() + " chars>");

        // Print full CSR PEM for verification
        log("2J      ", "");
        log("2J      ", "=== CSR PEM Output ===");
        System.out.println(csrPem);
        log("2J      ", "=== End CSR PEM ===");

        // Print summary of what Sub CA will receive
        log("SUMMARY ", "CSR Subject    : " + csr.getSubject());
        log("SUMMARY ", "CSR Sig Alg    : " + csr.getSignatureAlgorithm().getAlgorithm().getId());
        log("SUMMARY ", "CSR Extensions : SAN, KeyUsage, EKU, BasicConstraints, SKID");
        log("SUMMARY ", "CSR ready for  : Step03_CsrSubmissionToSubCa");

        return csr;
    }

    private static void saveCsrPem(String pem) throws IOException {
        Files.createDirectories(Paths.get("cert"));
        try (FileWriter fw = new FileWriter("cert/server.csr.pem")) {
            fw.write(pem);
        }
    }

    static void log(String tag, String message) {
        System.out.printf("[STEP02][%-8s] %s%n", tag, message);
    }
}
