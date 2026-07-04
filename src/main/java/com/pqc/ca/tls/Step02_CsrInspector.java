package com.pqc.ca.tls;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.math.BigInteger;
import java.security.Security;
import java.util.Enumeration;

/**
 * Parses cert/server.csr.pem and prints every ASN.1 field and OID
 * found in the CSR — subject DN, public key, and all extensions.
 *
 * Run: {@code .\gradlew.bat csr-inspect}
 */
public class Step02_CsrInspector {

    // ── OID → human-readable name map (common X.509 OIDs) ───────────────────
    private static String oidName(String oid) {
        return switch (oid) {
            // DN attributes
            case "2.5.4.3"  -> "CN  (commonName)";
            case "2.5.4.5"  -> "SN  (serialNumber / device)";
            case "2.5.4.6"  -> "C   (countryName)";
            case "2.5.4.7"  -> "L   (localityName)";
            case "2.5.4.8"  -> "ST  (stateOrProvinceName)";
            case "2.5.4.9"  -> "STREET (streetAddress)";
            case "2.5.4.10" -> "O   (organizationName)";
            case "2.5.4.11" -> "OU  (organizationalUnitName)";
            case "2.5.4.15" -> "businessCategory";
            case "2.5.4.17" -> "postalCode";
            // Extensions
            case "2.5.29.14" -> "subjectKeyIdentifier";
            case "2.5.29.15" -> "keyUsage";
            case "2.5.29.17" -> "subjectAltName (SAN)";
            case "2.5.29.19" -> "basicConstraints";
            case "2.5.29.37" -> "extendedKeyUsage";
            case "2.5.29.32" -> "certificatePolicies";
            case "2.5.29.31" -> "cRLDistributionPoints";
            case "1.3.6.1.5.5.7.48.1" -> "OCSP";
            case "1.3.6.1.5.5.7.48.2" -> "caIssuers";
            // EKU key purposes
            case "1.3.6.1.5.5.7.3.1" -> "id-kp-serverAuth";
            case "1.3.6.1.5.5.7.3.2" -> "id-kp-clientAuth";
            case "1.3.6.1.5.5.7.3.3" -> "id-kp-codeSigning";
            case "1.3.6.1.5.5.7.3.4" -> "id-kp-emailProtection";
            case "1.3.6.1.5.5.7.3.8" -> "id-kp-timeStamping";
            // PKCS#9
            case "1.2.840.113549.1.9.14" -> "pkcs-9-at-extensionRequest";
            // Public key algorithms
            case "1.2.840.113549.1.1.1"  -> "rsaEncryption";
            case "1.2.840.113549.1.1.11" -> "sha256WithRSAEncryption";
            case "1.2.840.10040.4.1"     -> "dsa";
            case "1.2.840.10045.2.1"     -> "ecPublicKey";
            default -> oid;
        };
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String csrPath = "cert/server.csr.pem";
        log("══════════════════════════════════════════════════════════════");
        log("  CSR ASN.1 Inspector — " + csrPath);
        log("══════════════════════════════════════════════════════════════");

        // ── Load PEM ────────────────────────────────────────────────────────
        PKCS10CertificationRequest csr;
        try (PemReader pr = new PemReader(new FileReader(csrPath))) {
            PemObject pem = pr.readPemObject();
            if (pem == null) throw new IllegalStateException("No PEM object found in " + csrPath);
            csr = new PKCS10CertificationRequest(pem.getContent());
        }
        log("[PEM]  Type    : CERTIFICATE REQUEST");
        log("[PEM]  File    : " + csrPath);

        // ── Section 1: Signature Algorithm ──────────────────────────────────
        section("1. Signature Algorithm");
        String sigAlgOid = csr.getSignatureAlgorithm().getAlgorithm().getId();
        log("  OID    : " + sigAlgOid);
        log("  Name   : " + oidName(sigAlgOid));

        // ── Section 2: Subject DN ────────────────────────────────────────────
        section("2. Subject Distinguished Name (DN)");
        org.bouncycastle.asn1.x500.X500Name subject = csr.getSubject();
        org.bouncycastle.asn1.x500.RDN[] rdns = subject.getRDNs();
        log("  Total RDNs : " + rdns.length);
        for (org.bouncycastle.asn1.x500.RDN rdn : rdns) {
            for (org.bouncycastle.asn1.x500.AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                String oid = atv.getType().getId();
                String val = atv.getValue().toString();
                log(String.format("  [%-40s] = %s", oidName(oid) + "  OID:" + oid, val));
            }
        }

        // ── Section 3: Public Key ────────────────────────────────────────────
        section("3. SubjectPublicKeyInfo");
        SubjectPublicKeyInfo spki = csr.getSubjectPublicKeyInfo();
        String keyAlgOid = spki.getAlgorithm().getAlgorithm().getId();
        log("  Algorithm OID : " + keyAlgOid);
        log("  Algorithm     : " + oidName(keyAlgOid));
        // Parse RSA public key to get modulus size
        try {
            org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPub =
                org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(spki.parsePublicKey());
            BigInteger modulus  = rsaPub.getModulus();
            BigInteger exponent = rsaPub.getPublicExponent();
            log("  Key Size      : " + modulus.bitLength() + " bits");
            log("  Public Exp    : " + exponent + " (0x" + exponent.toString(16) + ")");
            log("  Modulus (hex) : " + modulus.toString(16).substring(0, 32) + "...");
        } catch (Exception e) {
            log("  (non-RSA key, raw SPKI shown)");
        }

        // ── Section 4: PKCS#9 Attributes ────────────────────────────────────
        section("4. PKCS#9 Attributes");
        org.bouncycastle.asn1.pkcs.Attribute[] allAttrs = csr.getAttributes();
        log("  Total attributes : " + allAttrs.length);
        for (org.bouncycastle.asn1.pkcs.Attribute attr : allAttrs) {
            String attrOid = attr.getAttrType().getId();
            log("  ┌─ Attribute OID : " + attrOid + "  [" + oidName(attrOid) + "]");
        }

        // ── Section 5: Extensions (from extensionRequest attribute) ──────────
        section("5. Requested Extensions (pkcs-9-at-extensionRequest)");
        org.bouncycastle.asn1.pkcs.Attribute[] extAttrs =
            csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

        if (extAttrs == null || extAttrs.length == 0) {
            log("  (no extensionRequest attribute found)");
            return;
        }

        // Re-encode → fresh DER parse to avoid DLSequence errors
        byte[] encoded = extAttrs[0].getAttrValues().getObjectAt(0)
            .toASN1Primitive().getEncoded(ASN1Encoding.DER);
        Extensions extensions = Extensions.getInstance(ASN1Primitive.fromByteArray(encoded));

        ASN1ObjectIdentifier[] extOids = extensions.getExtensionOIDs();
        log("  Total extensions : " + extOids.length);

        for (ASN1ObjectIdentifier extOid : extOids) {
            Extension ext = extensions.getExtension(extOid);
            printExtension(extOid, ext);
        }

        // ── Section 6: Raw ASN.1 dump of entire CertificationRequestInfo ────
        section("6. Raw ASN.1 Dump — CertificationRequestInfo");
        ASN1Primitive tbsDer = ASN1Primitive.fromByteArray(csr.toASN1Structure()
            .getCertificationRequestInfo().getEncoded(ASN1Encoding.DER));
        dumpAsn1(tbsDer, "  ", 0);

        log("\n══════════════════════════════════════════════════════════════");
        log("  Inspection complete.");
        log("══════════════════════════════════════════════════════════════");
    }

    // ── Per-extension decoder ────────────────────────────────────────────────

    private static void printExtension(ASN1ObjectIdentifier oid, Extension ext) {
        String oidStr  = oid.getId();
        String name    = oidName(oidStr);
        boolean critical = ext.isCritical();

        log("\n  ┌──────────────────────────────────────────────────────");
        log("  │ OID      : " + oidStr);
        log("  │ Name     : " + name);
        log("  │ Critical : " + critical);

        // Decode extnValue OCTET STRING → raw extension bytes
        byte[] valBytes = ext.getExtnValue().getOctets();

        try {
            if (oid.equals(Extension.subjectAlternativeName)) {
                printSan(valBytes);

            } else if (oid.equals(Extension.keyUsage)) {
                printKeyUsage(valBytes);

            } else if (oid.equals(Extension.extendedKeyUsage)) {
                printEku(valBytes);

            } else if (oid.equals(Extension.basicConstraints)) {
                printBasicConstraints(valBytes);

            } else if (oid.equals(Extension.subjectKeyIdentifier)) {
                printSkid(valBytes);

            } else if (oid.equals(Extension.authorityKeyIdentifier)) {
                printAkid(valBytes);

            } else {
                // Unknown extension — dump raw ASN.1
                log("  │ Value    : (raw ASN.1)");
                dumpAsn1(ASN1Primitive.fromByteArray(valBytes), "  │   ", 0);
            }
        } catch (Exception e) {
            log("  │ ⚠ Parse error: " + e.getMessage());
        }

        log("  └──────────────────────────────────────────────────────");
    }

    // ── SAN decoder ─────────────────────────────────────────────────────────

    private static void printSan(byte[] bytes) throws Exception {
        GeneralNames gns = GeneralNames.getInstance(ASN1Primitive.fromByteArray(bytes));
        log("  │ Type     : SubjectAlternativeName");
        log("  │ Entries  : " + gns.getNames().length);
        for (GeneralName gn : gns.getNames()) {
            String type = switch (gn.getTagNo()) {
                case GeneralName.rfc822Name              -> "rfc822Name (email)";
                case GeneralName.dNSName                 -> "dNSName";
                case GeneralName.uniformResourceIdentifier -> "URI";
                case GeneralName.iPAddress               -> "iPAddress";
                case GeneralName.registeredID            -> "registeredID";
                case GeneralName.directoryName           -> "directoryName";
                default                                  -> "tag[" + gn.getTagNo() + "]";
            };
            String value = gn.getName().toString();
            // iPAddress: raw bytes → dotted decimal
            if (gn.getTagNo() == GeneralName.iPAddress) {
                byte[] ip = DEROctetString.getInstance(gn.getName()).getOctets();
                if (ip.length == 4) {
                    value = (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "."
                          + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
                }
            }
            log("  │   [" + type + "] = " + value);
        }
    }

    // ── KeyUsage decoder ─────────────────────────────────────────────────────

    private static void printKeyUsage(byte[] bytes) throws Exception {
        KeyUsage ku = KeyUsage.getInstance(ASN1Primitive.fromByteArray(bytes));
        log("  │ Type     : KeyUsage (BIT STRING)");
        String[] bits = {
            "digitalSignature", "nonRepudiation", "keyEncipherment",
            "dataEncipherment", "keyAgreement",   "keyCertSign",
            "cRLSign",          "encipherOnly",    "decipherOnly"
        };
        for (int i = 0; i < bits.length; i++) {
            boolean set = ku.hasUsages(1 << (8 - i - (i < 7 ? 0 : 1)));
            if (i == 0) set = ku.hasUsages(KeyUsage.digitalSignature);
            if (i == 1) set = ku.hasUsages(KeyUsage.nonRepudiation);
            if (i == 2) set = ku.hasUsages(KeyUsage.keyEncipherment);
            if (i == 3) set = ku.hasUsages(KeyUsage.dataEncipherment);
            if (i == 4) set = ku.hasUsages(KeyUsage.keyAgreement);
            if (i == 5) set = ku.hasUsages(KeyUsage.keyCertSign);
            if (i == 6) set = ku.hasUsages(KeyUsage.cRLSign);
            if (i == 7) set = ku.hasUsages(KeyUsage.encipherOnly);
            if (i == 8) set = ku.hasUsages(KeyUsage.decipherOnly);
            log("  │   " + (set ? "✔" : "✗") + " " + bits[i]);
        }
    }

    // ── ExtendedKeyUsage decoder ─────────────────────────────────────────────

    private static void printEku(byte[] bytes) throws Exception {
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ASN1Primitive.fromByteArray(bytes));
        log("  │ Type     : ExtendedKeyUsage (SEQUENCE OF OID)");
        for (KeyPurposeId kp : eku.getUsages()) {
            String oidStr = kp.getId();
            log("  │   OID : " + oidStr + "  [" + oidName(oidStr) + "]");
        }
    }

    // ── BasicConstraints decoder ─────────────────────────────────────────────

    private static void printBasicConstraints(byte[] bytes) throws Exception {
        BasicConstraints bc = BasicConstraints.getInstance(ASN1Primitive.fromByteArray(bytes));
        log("  │ Type         : BasicConstraints");
        log("  │ isCA         : " + bc.isCA());
        log("  │ pathLen      : " + (bc.getPathLenConstraint() != null
            ? bc.getPathLenConstraint().toString() : "not set"));
    }

    // ── SubjectKeyIdentifier decoder ─────────────────────────────────────────

    private static void printSkid(byte[] bytes) throws Exception {
        SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(
            ASN1Primitive.fromByteArray(bytes));
        byte[] keyId = skid.getKeyIdentifier();
        log("  │ Type     : SubjectKeyIdentifier");
        log("  │ Length   : " + keyId.length + " bytes");
        log("  │ Value    : " + toHex(keyId));
    }

    // ── AuthorityKeyIdentifier decoder ────────────────────────────────────────

    private static void printAkid(byte[] bytes) throws Exception {
        AuthorityKeyIdentifier akid = AuthorityKeyIdentifier.getInstance(
            ASN1Primitive.fromByteArray(bytes));
        byte[] keyId = akid.getKeyIdentifier();
        log("  │ Type     : AuthorityKeyIdentifier");
        if (keyId != null) {
            log("  │ KeyId    : " + toHex(keyId));
        }
        if (akid.getAuthorityCertSerialNumber() != null) {
            log("  │ Serial   : " + akid.getAuthorityCertSerialNumber());
        }
    }

    // ── Raw ASN.1 recursive dump ─────────────────────────────────────────────

    private static void dumpAsn1(ASN1Primitive obj, String indent, int depth) {
        if (depth > 8) { log(indent + "... (max depth)"); return; }
        if (obj instanceof ASN1Sequence seq) {
            log(indent + "SEQUENCE [" + seq.size() + " elements]");
            Enumeration<?> e = seq.getObjects();
            while (e.hasMoreElements()) {
                try { dumpAsn1(((ASN1Encodable) e.nextElement()).toASN1Primitive(),
                               indent + "  ", depth + 1); }
                catch (Exception ex) { log(indent + "  (parse error: " + ex.getMessage() + ")"); }
            }
        } else if (obj instanceof ASN1Set set) {
            log(indent + "SET [" + set.size() + " elements]");
            Enumeration<?> e = set.getObjects();
            while (e.hasMoreElements()) {
                try { dumpAsn1(((ASN1Encodable) e.nextElement()).toASN1Primitive(),
                               indent + "  ", depth + 1); }
                catch (Exception ex) { log(indent + "  (parse error: " + ex.getMessage() + ")"); }
            }
        } else if (obj instanceof ASN1ObjectIdentifier oidObj) {
            log(indent + "OID  : " + oidObj.getId() + "  [" + oidName(oidObj.getId()) + "]");
        } else if (obj instanceof ASN1OctetString oct) {
            byte[] b = oct.getOctets();
            log(indent + "OCTET STRING [" + b.length + " bytes] : " + toHexShort(b));
        } else if (obj instanceof ASN1BitString bits) {
            log(indent + "BIT STRING [" + bits.getBytes().length + " bytes] : "
                + toHexShort(bits.getBytes()));
        } else if (obj instanceof ASN1Boolean bool) {
            log(indent + "BOOLEAN : " + bool.isTrue());
        } else if (obj instanceof ASN1Integer integer) {
            log(indent + "INTEGER : " + integer.getValue());
        } else if (obj instanceof ASN1UTF8String s) {
            log(indent + "UTF8String : " + s.getString());
        } else if (obj instanceof ASN1PrintableString s) {
            log(indent + "PrintableString : " + s.getString());
        } else if (obj instanceof DERIA5String s) {
            log(indent + "IA5String : " + s.getString());
        } else if (obj instanceof ASN1TaggedObject tagged) {
            log(indent + "TAGGED [" + tagged.getTagNo() + "] explicit=" + tagged.hasContextTag());
            try { dumpAsn1(tagged.getBaseObject().toASN1Primitive(), indent + "  ", depth + 1); }
            catch (Exception ex) { log(indent + "  (parse error: " + ex.getMessage() + ")"); }
        } else if (obj instanceof ASN1Null) {
            log(indent + "NULL");
        } else {
            log(indent + obj.getClass().getSimpleName() + " : " + obj);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X:", b));
        if (!sb.isEmpty()) sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private static String toHexShort(byte[] bytes) {
        if (bytes.length <= 12) return toHex(bytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i++) sb.append(String.format("%02X", bytes[i]));
        return sb + "... (" + bytes.length + " bytes total)";
    }

    private static void section(String title) {
        log("\n── " + title + " " + "─".repeat(Math.max(0, 54 - title.length())));
    }

    private static void log(String msg) {
        System.out.println(msg);
    }
}
