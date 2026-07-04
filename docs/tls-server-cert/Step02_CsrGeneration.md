# Step 02 — CSR Generation with Maximum Granular Attributes

## Overview

A **CSR (Certificate Signing Request)** — formally **PKCS#10** (RFC 2986) — is a digitally signed message sent from a certificate applicant to a Certificate Authority. It contains:

1. The applicant's **Distinguished Name (DN)**
2. The applicant's **public key**
3. Requested **X.509v3 extensions**
4. A **digital signature** made with the applicant's private key

The CA verifies the CSR signature, validates the identity, then issues a certificate binding the DN and public key together under the CA's own signature.

---

## Why CSR? (Proof of Possession)

The CSR signature serves as **Proof of Possession (PoP)** — it mathematically proves the requester controls the private key corresponding to the public key they are requesting a certificate for.

Without this proof, an attacker could submit someone else's public key and get a certificate for it, enabling impersonation.

```
Server generates:   privateKey  +  publicKey
                        │               │
                        │         CSR contains publicKey
                        │               │
                        └──sign(CSR)────┘
                            ▲
                  Sub CA verifies: CSR signature valid?
                  If yes → trust that server owns the private key
```

---

## PKCS#10 Structure (RFC 2986)

```asn1
CertificationRequest ::= SEQUENCE {
    certificationRequestInfo  CertificationRequestInfo,
    signatureAlgorithm        AlgorithmIdentifier,
    signature                 BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
    version       INTEGER { v1(0) },
    subject       Name,                         ← X.500 DN
    subjectPKInfo SubjectPublicKeyInfo,          ← public key
    attributes    [0] IMPLICIT Attributes OPTIONAL  ← extensions go here
}
```

The **attributes** field carries a `pkcs-9-at-extensionRequest` attribute, which is a bag of X.509v3 extensions the applicant is *requesting*. The CA may honour all, some, or none of them.

---

## Sub-step 2A: Key Pair Load

```
Input:  TlsCertStore.serverKeyPair (from Step01)
        If null → Step01_ServerKeyPairGeneration.generateServerKeyPair() called inline
Output: RSA-2048 KeyPair available in memory
```

**Why check null?** Each Java process starts fresh — TlsCertStore static fields reset. In production, Step01 runs in the same JVM session so the key pair is already in memory. The null-check makes Step02 standalone-runnable for testing.

---

## Sub-step 2B: X500Name — 10 DN Attributes

The Distinguished Name (DN) is the **identity claim** in the CSR. The CA will copy the DN (possibly modified) into the issued certificate's Subject field.

### Attribute Table

| OID | Short Name | Value | Purpose |
|-----|-----------|-------|---------|
| 2.5.4.6 | C | `IN` | Country (ISO 3166-1 alpha-2) |
| 2.5.4.8 | ST | `Maharashtra` | State or Province |
| 2.5.4.7 | L | `Mumbai` | Locality (City) |
| 2.5.4.9 | STREET | `123 Tech Park, Andheri East` | Street Address |
| 2.5.4.17 | PostalCode | `400069` | Postal/ZIP Code |
| 2.5.4.10 | O | `Salman Technologies Pvt Ltd` | Organization (legal name) |
| 2.5.4.11 | OU | `IT Infrastructure` | Organizational Unit |
| 2.5.4.15 | businessCategory | `Internet Service Provider` | Nature of business |
| 2.5.4.5 | serialNumber | `SRV-2026-001` | Device/Server identifier |
| 2.5.4.3 | CN | `api.salman.com` | Common Name (primary hostname) |

### DN String Output

```
C=IN, ST=Maharashtra, L=Mumbai,
STREET=123 Tech Park\, Andheri East,
PostalCode=400069,
O=Salman Technologies Pvt Ltd,
OU=IT Infrastructure,
BusinessCategory=Internet Service Provider,
SERIALNUMBER=SRV-2026-001,
CN=api.salman.com
```

### Notes

- **C** must be exactly 2 uppercase characters (PRINTABLESTRING constraint)
- **CN** should match your primary hostname; browsers use SAN, not CN, but CN is still important for human readability and legacy clients
- **serialNumber** here is the *device* serial number — different from the *certificate* serial number assigned by the CA
- **businessCategory** is used in Extended Validation (EV) certificates to describe the type of organization
- **X500NameBuilder** in BouncyCastle builds the RDN sequence internally; last `addRDN()` call = most specific attribute in the printed order

### Code

```java
X500NameBuilder dnBuilder = new X500NameBuilder(BCStyle.INSTANCE);
dnBuilder.addRDN(BCStyle.C,                 "IN");
dnBuilder.addRDN(BCStyle.ST,                "Maharashtra");
dnBuilder.addRDN(BCStyle.L,                 "Mumbai");
dnBuilder.addRDN(BCStyle.STREET,            "123 Tech Park, Andheri East");
dnBuilder.addRDN(BCStyle.POSTAL_CODE,       "400069");
dnBuilder.addRDN(BCStyle.O,                 "Salman Technologies Pvt Ltd");
dnBuilder.addRDN(BCStyle.OU,                "IT Infrastructure");
dnBuilder.addRDN(BCStyle.BUSINESS_CATEGORY, "Internet Service Provider");
dnBuilder.addRDN(BCStyle.SERIALNUMBER,      "SRV-2026-001");
dnBuilder.addRDN(BCStyle.CN,                "api.salman.com");
X500Name subject = dnBuilder.build();
```

---

## Sub-step 2C: Subject Alternative Names (SAN)

SAN is **the** authoritative extension for hostname binding in TLS (RFC 2818 §3.1). Modern clients (Chrome, Firefox, Java, curl) **ignore CN** when SAN is present.

### SAN Entries

| Type | Value | GeneralName Tag |
|------|-------|----------------|
| dNSName | `api.salman.com` | [2] |
| dNSName | `www.salman.com` | [2] |
| dNSName | `admin.salman.com` | [2] |
| iPAddress | `192.168.1.100` | [7] |

### GeneralName Types (RFC 5280 §4.2.1.6)

```
[0] otherName       — custom OID-keyed names
[1] rfc822Name      — email address (for S/MIME)
[2] dNSName         — hostname (TLS)
[3] x400Address     — X.400 email (legacy)
[4] directoryName   — X.500 DN
[5] ediPartyName    — EDI systems (rare)
[6] uniformResourceIdentifier — URI
[7] iPAddress       — IPv4 (4 bytes) or IPv6 (16 bytes)
[8] registeredID    — OID
```

### Code

```java
GeneralName[] sanEntries = new GeneralName[] {
    new GeneralName(GeneralName.dNSName, "api.salman.com"),
    new GeneralName(GeneralName.dNSName, "www.salman.com"),
    new GeneralName(GeneralName.dNSName, "admin.salman.com"),
    new GeneralName(GeneralName.iPAddress, "192.168.1.100")
};
GeneralNames subjectAltNames = new GeneralNames(sanEntries);
```

---

## Sub-step 2D: KeyUsage Extension

Controls *what cryptographic operations* the key may be used for.

| Bit | Name | Set? | Reason |
|-----|------|------|--------|
| 0 | digitalSignature | ✅ | Signs TLS handshake messages |
| 1 | nonRepudiation | ❌ | Document signing, not TLS |
| 2 | keyEncipherment | ✅ | Encrypts pre-master secret (RSA key exchange) |
| 3 | dataEncipherment | ❌ | S/MIME, not TLS |
| 5 | keyCertSign | ❌ | Only for CAs |
| 6 | cRLSign | ❌ | Only for CAs |

**Critical = true** — RFC 5280 §4.2.1.3 requires KeyUsage to be critical when present in a CA-issued certificate. If not critical, a relying party may ignore it.

```java
KeyUsage keyUsage = new KeyUsage(
    KeyUsage.digitalSignature | KeyUsage.keyEncipherment
);
```

---

## Sub-step 2E: ExtendedKeyUsage (EKU)

Narrows the allowed usage further — like a VISA specifying which countries you can enter.

| OID | Name | Purpose |
|-----|------|---------|
| 1.3.6.1.5.5.7.3.1 | id-kp-serverAuth | TLS Web Server Authentication ✅ |
| 1.3.6.1.5.5.7.3.2 | id-kp-clientAuth | TLS Client Authentication |
| 1.3.6.1.5.5.7.3.3 | id-kp-codeSigning | Code Signing |
| 1.3.6.1.5.5.7.3.4 | id-kp-emailProtection | S/MIME |
| 1.3.6.1.5.5.7.3.8 | id-kp-timeStamping | RFC 3161 timestamping |

**Browsers require** `id-kp-serverAuth` since ~2020. Without it, Chrome/Firefox show NET::ERR_CERT_INVALID.

```java
ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
    KeyPurposeId.id_kp_serverAuth
);
```

---

## Sub-step 2F: BasicConstraints

Declares whether this is a CA certificate or an end-entity certificate.

```
BasicConstraints ::= SEQUENCE {
    cA                      BOOLEAN DEFAULT FALSE,
    pathLenConstraint       INTEGER (0..MAX) OPTIONAL
}
```

For a TLS server certificate: `isCA=false`, no `pathLenConstraint`.

**Critical = true** — If not critical and isCA were somehow set to true, a stolen server cert could be used to create a rogue sub-CA and issue fraudulent certs. Making it critical forces all compliant software to honour it.

```java
BasicConstraints basicConstraints = new BasicConstraints(false);
```

---

## Sub-step 2G: SubjectKeyIdentifier (SKID)

A hash of the public key — used to correlate certificates, CRLs, and OCSP responses with a specific key.

**Computation (RFC 5280 §4.2.1.2, Method 1):**
```
SKID = SHA-1( subjectPublicKey bit string )
```

Note: this is SHA-1 of the *bit string* contents, not the full SubjectPublicKeyInfo DER. BouncyCastle's `JcaX509ExtensionUtils.createSubjectKeyIdentifier()` implements this correctly.

```java
JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
SubjectKeyIdentifier skid = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
```

---

## Sub-step 2H: Build and Sign PKCS#10 CSR

```java
// Pack extensions
ExtensionsGenerator extGen = new ExtensionsGenerator();
extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
extGen.addExtension(Extension.keyUsage,               true,  keyUsage);
extGen.addExtension(Extension.extendedKeyUsage,       false, extendedKeyUsage);
extGen.addExtension(Extension.basicConstraints,       true,  basicConstraints);
extGen.addExtension(Extension.subjectKeyIdentifier,   false, skid);

// Build CSR
JcaPKCS10CertificationRequestBuilder csrBuilder =
    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

// Attach extensions as pkcs-9-at-extensionRequest attribute
csrBuilder.addAttribute(
    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
    extGen.generate()
);

// Sign with server's private key
ContentSigner csrSigner = new JcaContentSignerBuilder("SHA256withRSA")
    .setProvider("BC")
    .build(keyPair.getPrivate());

PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);
```

### Signature Algorithm Choice

| Algorithm | Security | Use Case |
|-----------|----------|----------|
| SHA1withRSA | ❌ Deprecated | Legacy only |
| SHA256withRSA | ✅ Standard | TLS server certs (2026) |
| SHA384withRSA | ✅ High security | CA certs |
| SHA512withRSA | ✅ Maximum | HSM-protected root CAs |

TLS server CSRs use SHA256withRSA — sufficient for 2048-bit RSA through 2030+.

---

## Sub-step 2I: Save cert/server.csr.pem

```
cert/
└── server.csr.pem    ← PKCS#10 CSR in PEM format
```

**PEM format:**
```
-----BEGIN CERTIFICATE REQUEST-----
<Base64-encoded DER, 64-char lines>
-----END CERTIFICATE REQUEST-----
```

`cert/server.csr.pem` is what you would submit to:
- An internal Sub CA (Step03 in this pipeline)
- A public CA (DigiCert, Let's Encrypt) via their portal or ACME protocol
- An enterprise CA (EJBCA, Microsoft CA) via their RA interface

---

## Sub-step 2J: Store in TlsCertStore

```java
TlsCertStore.serverCsr = csr;    // PKCS10CertificationRequest object
TlsCertStore.csrPem    = csrPem; // PEM string
```

Step03 reads `TlsCertStore.serverCsr` to:
1. Verify the CSR signature (proof of possession check)
2. Extract the subject DN and public key
3. Validate the requested extensions
4. Submit to Sub CA for issuance

---

## Expected Log Output

```
[STEP02][INIT    ] ============================================================
[STEP02][INIT    ]   Step 02 — CSR Generation with Maximum Granular Attributes
[STEP02][INIT    ] ============================================================
[STEP02][2A      ] --- Sub-step 2A: Load Server Key Pair ---
[STEP02][2A      ] Key pair loaded from TlsCertStore.serverKeyPair
[STEP02][2A      ] Public key algorithm : RSA
[STEP02][2A      ] Public key format    : X.509
[STEP02][2B      ] --- Sub-step 2B: Build X500Name (DN) with 10 attributes ---
[STEP02][2B      ]   C  (Country)            = IN
[STEP02][2B      ]   ST (State)              = Maharashtra
[STEP02][2B      ]   L  (Locality)           = Mumbai
[STEP02][2B      ]   STREET                  = 123 Tech Park, Andheri East
[STEP02][2B      ]   PostalCode              = 400069
[STEP02][2B      ]   O  (Organization)       = Salman Technologies Pvt Ltd
[STEP02][2B      ]   OU (Org Unit)           = IT Infrastructure
[STEP02][2B      ]   businessCategory        = Internet Service Provider
[STEP02][2B      ]   serialNumber (device)   = SRV-2026-001
[STEP02][2B      ]   CN (Common Name)        = api.salman.com
[STEP02][2C      ] --- Sub-step 2C: Subject Alternative Names (SAN) ---
[STEP02][2C      ]   SAN[0] dNSName   = api.salman.com
[STEP02][2C      ]   SAN[1] dNSName   = www.salman.com
[STEP02][2C      ]   SAN[2] dNSName   = admin.salman.com
[STEP02][2C      ]   SAN[3] iPAddress = 192.168.1.100
[STEP02][2D      ] --- Sub-step 2D: KeyUsage Extension ---
[STEP02][2D      ]   KeyUsage = digitalSignature | keyEncipherment  (critical=true)
[STEP02][2E      ] --- Sub-step 2E: ExtendedKeyUsage Extension ---
[STEP02][2E      ]   EKU = id-kp-serverAuth (1.3.6.1.5.5.7.3.1)
[STEP02][2F      ] --- Sub-step 2F: BasicConstraints (isCA=false) ---
[STEP02][2F      ]   BasicConstraints isCA=false  (critical=true)
[STEP02][2G      ] --- Sub-step 2G: SubjectKeyIdentifier (SKID) ---
[STEP02][2G      ]   SKID computed from SHA-1(SubjectPublicKeyInfo)
[STEP02][2H      ] --- Sub-step 2H: Build PKCS#10 CSR and Sign ---
[STEP02][2H      ] ExtensionsGenerator: 5 extensions packed
[STEP02][2H      ] extensionRequest attribute added to CSR
[STEP02][2H      ] CSR signer: SHA256withRSA with server private key
[STEP02][2H      ] PKCS#10 CSR built and signed successfully
[STEP02][2H      ] CSR DER size : 1014 bytes
[STEP02][2H      ] CSR PEM size : 1444 chars
[STEP02][2I      ] Saved: cert/server.csr.pem
[STEP02][2J      ] TlsCertStore.serverCsr  = <PKCS10CertificationRequest>
[STEP02][2J      ] TlsCertStore.csrPem     = <PEM string>
[STEP02][SUMMARY ] CSR Subject    : C=IN,ST=Maharashtra,...,CN=api.salman.com
[STEP02][SUMMARY ] CSR Sig Alg    : 1.2.840.113549.1.1.11
[STEP02][SUMMARY ] CSR Extensions : SAN, KeyUsage, EKU, BasicConstraints, SKID
[STEP02][SUMMARY ] CSR ready for  : Step03_CsrSubmissionToSubCa
[STEP02][DONE    ] Step 02 Complete — CSR saved to cert/server.csr.pem
[STEP02][DONE    ] Next Step → Step03_CsrSubmissionToSubCa.java
```

---

## Extensions Summary

| Extension | Critical | Value | RFC |
|-----------|----------|-------|-----|
| subjectAlternativeName | false | 3 DNS + 1 IP | RFC 5280 §4.2.1.6 |
| keyUsage | **true** | digitalSignature, keyEncipherment | RFC 5280 §4.2.1.3 |
| extendedKeyUsage | false | id-kp-serverAuth | RFC 5280 §4.2.1.12 |
| basicConstraints | **true** | isCA=false | RFC 5280 §4.2.1.9 |
| subjectKeyIdentifier | false | SHA-1(pubkey) | RFC 5280 §4.2.1.2 |

---

## Files Produced

| File | Format | Description |
|------|--------|-------------|
| `cert/server.csr.pem` | PKCS#10 PEM | CSR for submission to Sub CA |

---

## Run Command

```bash
.\gradlew.bat run -PmainClass=com.pqc.ca.tls.Step02_CsrGeneration
```

---

## Pipeline Position

```
Step01_ServerKeyPairGeneration  ──► Step02_CsrGeneration  ──► Step03_CsrSubmissionToSubCa
      (RSA-2048 KeyPair)               (PKCS#10 CSR)              (CA validates + queues)
```

---

## Security Checklist

- [ ] CSR private key stored securely (never transmitted, never logged)
- [ ] SAN includes all hostnames clients will connect to
- [ ] KeyUsage limited to `digitalSignature | keyEncipherment` only
- [ ] EKU set to `id-kp-serverAuth` (required by browsers)
- [ ] BasicConstraints `isCA=false` and critical
- [ ] CN matches primary hostname in SAN
- [ ] CSR signature verified by Sub CA before issuance (Step03)
- [ ] `cert/server.csr.pem` file permissions: readable by CA system only
