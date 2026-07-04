# Step 01 — TLS Server Key Pair Generation

**Package:** `com.pqc.ca.tls`  
**File:** `Step01_ServerKeyPairGeneration.java`  
**Output:** `cert/server.key.pem`, `cert/server.pub.pem`  
**Run:** `.\gradlew.bat run -PmainClass=com.pqc.ca.tls.Step01_ServerKeyPairGeneration`

---

## Is Step Ka Purpose

TLS Server certificate banane ka **pehla kaam** hota hai ek key pair generate karna.

```
Server                              CA (Sub CA)
  |                                     |
  |-- [1] Key Pair Generate karo        |
  |       Private Key → apne paas rakho |
  |       Public Key  → CSR mein daalo  |
  |                                     |
  |-- [2] CSR banao (Step02) ---------->|
  |                                     |-- Certificate sign karo (Step04)
  |<----------------------------------- |
  |-- [3] Certificate mile              |
```

---

## Concept: Key Pair Kya Hota Hai?

### Private Key
```
Secret → sirf server ke paas
Kaam  → TLS handshake mein identity prove karna
        Client ka data decrypt karna
Rule  → NEVER share, NEVER log, NEVER git commit
```

### Public Key
```
Public → sab dekh sakte hain
Kaam  → Certificate mein embed hoti hai
        Client server se encrypt karta hai
Rule  → Freely distribute karo
```

---

## RSA-2048 Kyu?

| Property | Value | Reason |
|---|---|---|
| Key Size | 2048 bits | NIST approved till ~2030, TLS server ke liye standard |
| Algorithm | RSA | Universal TLS support, hardware acceleration available |
| Root CA | 4096 bits | 20 year lifetime → stronger key chahiye |
| Sub CA | 2048 bits | 10 year lifetime → 2048 kaafi |
| Server | 2048 bits | 1 year cert → 2048 secure, faster handshake |

---

## RSA Key Generation — Andar Kya Hota Hai?

```
Step A: Entropy collect karo
        OS se SecureRandom → /dev/urandom (Linux) ya CryptGenRandom (Windows)
        ↓
Step B: Prime p generate karo (~1024 bits)
        Random odd number lo → Miller-Rabin primality test → repeat until prime
        ↓
Step C: Prime q generate karo (~1024 bits)
        Same process, ensure p ≠ q
        ↓
Step D: Modulus n = p × q
        n = 2048-bit number (yeh RSA key size hai)
        ↓
Step E: Public exponent e = 65537
        Standard Fermat prime F4 = 2^16 + 1
        Binary: 10000000000000001 (sirf 2 set bits → fast)
        ↓
Step F: Private exponent d = e⁻¹ mod λ(n)
        λ(n) = lcm(p-1, q-1)
        ↓
Step G: CRT components compute karo
        dp = d mod (p-1)
        dq = d mod (q-1)
        qInv = q⁻¹ mod p
        → 4x faster decryption
```

---

## Code Flow — Step by Step

### Sub-Step 1A: BouncyCastle Register

```java
Security.insertProviderAt(new BouncyCastleProvider(), 1);
```

**Kyu?**
- Position 1 = highest priority
- BC ke bina: PKCS#10 CSR (Step02) aur X.509 cert building (Step04) nahi chalega
- BC = PKCS#8, PKCS#10, X.509, CRL, OCSP — sab ek jagah

**Log output:**
```
[STEP01][PROVIDER ] BouncyCastle registered at position 1 (highest priority)
[STEP01][PROVIDER ] Active JCE providers:
[STEP01][PROVIDER ]   [1] BC v1.8
[STEP01][PROVIDER ]   [2] SUN v21.0
```

---

### Sub-Step 1B: cert/ Directory Create

```java
Files.createDirectories(Paths.get("cert"));
```

**Kyu?**
- Keys aur certs source code se alag rakhte hain
- `.gitignore` mein `cert/` add karo — private key GitHub pe kabhi nahi jaani chahiye
- Directory nahi thi toh `FileNotFoundException` aata

**Log output:**
```
[STEP01][DIR      ] cert/ directory create ki gayi: C:\pqc-demo\cert
```

---

### Sub-Step 1C: Key Pair Generate

```java
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
keyGen.initialize(2048, new SecureRandom());
KeyPair keyPair = keyGen.generateKeyPair();
```

**Kyu `"BC"` explicitly?**
- Bina "BC" ke: JVM koi bhi provider use kar sakta hai
- "BC" explicitly → ensured hai ki BouncyCastle ka RSA implementation use ho
- Important jab multiple providers registered hों

**Log output:**
```
[STEP01][KEYGEN   ] KeyPairGenerator instance le rahe hain — Algorithm: RSA, Provider: BC
[STEP01][KEYGEN   ] Key size initialize kar rahe hain: 2048 bits
[STEP01][KEYGEN   ] Prime generation shuru... (p aur q dono ~1024-bit primes)
[STEP01][KEYGEN   ] Key pair generate hua in 214 ms
[STEP01][KEYGEN   ] Public key class : BCRSAPublicKey
[STEP01][KEYGEN   ] Private key class: BCRSACrtPrivateKey
```

---

### Sub-Step 1D: Public Key Inspect

```java
RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
pub.getModulus().bitLength()     // → 2048
pub.getPublicExponent()          // → 65537
pub.getEncoded().length          // → ~294 bytes DER
```

**Public Key ASN.1 Structure:**
```
SEQUENCE {
  SEQUENCE {
    OID 1.2.840.113549.1.1.1    -- rsaEncryption
    NULL
  }
  BIT STRING {
    SEQUENCE {
      INTEGER [modulus n]        -- 2048-bit number
      INTEGER 65537              -- public exponent e
    }
  }
}
```

**Log output:**
```
[STEP01][PUBKEY   ] Algorithm           : RSA
[STEP01][PUBKEY   ] Encoding Format     : X.509 (SubjectPublicKeyInfo ASN.1)
[STEP01][PUBKEY   ] Encoded Size        : 294 bytes (DER)
[STEP01][PUBKEY   ] Modulus Bit Length  : 2048 bits → RSA-2048 confirmed
[STEP01][PUBKEY   ] Public Exponent (e) : 65537 (Fermat prime F4, standard)
```

---

### Sub-Step 1E: Private Key Inspect (CRT Structure)

```java
RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();
priv.getPrimeP().bitLength()         // → ~1024 bits
priv.getPrimeQ().bitLength()         // → ~1024 bits
priv.getPrimeExponentP().bitLength() // → dp
priv.getPrimeExponentQ().bitLength() // → dq
priv.getCrtCoefficient().bitLength() // → qInv
```

**CRT Optimization kya hai?**

```
Without CRT:              With CRT:
m = c^d mod n            m1 = c^dp mod p   (1024-bit operation)
(2048-bit operation)      m2 = c^dq mod q   (1024-bit operation)
Very slow                 m  = CRT(m1,m2)   (fast combine)
                          → 4x faster!
```

**Log output:**
```
[STEP01][PRIVKEY  ] CRT Prime p bits    : 1024 bits
[STEP01][PRIVKEY  ] CRT Prime q bits    : 1024 bits
[STEP01][PRIVKEY  ] CRT dp (d mod p-1)  : 1023 bits
[STEP01][PRIVKEY  ] CRT dq (d mod q-1)  : 1024 bits
[STEP01][PRIVKEY  ] WHY CRT? → TLS handshake 4x faster with CRT vs naive RSA
```

---

### Sub-Step 1F: Private Key PEM Save

```java
// DER → Base64 → PEM wrap
String pem = "-----BEGIN PRIVATE KEY-----\n"
           + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded)
           + "\n-----END PRIVATE KEY-----\n";

new FileWriter("cert/server.key.pem").write(pem);
```

**PEM Format kya hai?**
```
-----BEGIN PRIVATE KEY-----       ← PKCS#8 marker (algorithm-agnostic)
MIIEvQIBADANBgkqhkiG9w0BAQEF     ← Base64 encoded DER bytes
AASCBKcwggSjAgEAAoIBAQC...       ← 64 chars per line (MIME encoding)
...
-----END PRIVATE KEY-----
```

**PKCS#8 vs PKCS#1:**

| Format | Header | Use |
|---|---|---|
| PKCS#8 | `BEGIN PRIVATE KEY` | Modern, algorithm-agnostic ✓ |
| PKCS#1 | `BEGIN RSA PRIVATE KEY` | Legacy RSA-only, avoid |
| Encrypted PKCS#8 | `BEGIN ENCRYPTED PRIVATE KEY` | Production use |

**Log output:**
```
[STEP01][SAVE     ] Private key DER encoded size: 1218 bytes
[STEP01][SAVE     ] Private key saved → C:\pqc-demo\cert\server.key.pem
[STEP01][SAVE     ] File size         : 1700 bytes
[STEP01][SAVE     ] WARNING           : Yeh file NEVER git commit karein!
```

---

### Sub-Step 1G: Public Key PEM Save

```java
String pem = "-----BEGIN PUBLIC KEY-----\n"
           + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded)
           + "\n-----END PUBLIC KEY-----\n";
```

**Log output:**
```
[STEP01][SAVE     ] Public key DER encoded size: 294 bytes
[STEP01][SAVE     ] Public key saved  → C:\pqc-demo\cert\server.pub.pem
[STEP01][SAVE     ] File size         : 450 bytes
```

---

### Sub-Step 1H: File Verification

```java
Files.exists(path) && Files.size(path) > 0
```

**Log output:**
```
[STEP01][VERIFY   ] cert/server.key.pem → exists=true, size=1700 bytes ✓
[STEP01][VERIFY   ] cert/server.pub.pem → exists=true, size=450 bytes ✓
```

---

## Generated Files

### `cert/server.key.pem`
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
[RSA-2048 private key — 1700 bytes approx]
-----END PRIVATE KEY-----
```

### `cert/server.pub.pem`
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
[RSA-2048 public key — 450 bytes approx]
-----END PUBLIC KEY-----
```

---

## Complete Log Output (Expected)

```
╔══════════════════════════════════════════════════════════════╗
║        TLS Server Certificate Pipeline                      ║
║        Step 01 — Server Key Pair Generation                 ║
╠══════════════════════════════════════════════════════════════╣
║  Package  : com.pqc.ca.tls                                  ║
║  Output   : cert/server.key.pem, cert/server.pub.pem        ║
║  Provider : BouncyCastle (bcprov + bcpkix)                  ║
╚══════════════════════════════════════════════════════════════╝

[STEP01][INIT     ] Starting Step 01 — TLS Server Key Pair Generation
[STEP01][INIT     ] BouncyCastle provider register kar rahe hain...
[STEP01][PROVIDER ] BouncyCastle registered at position 1 (highest priority)
[STEP01][PROVIDER ] Active JCE providers:
[STEP01][PROVIDER ]   [1] BC v1.8
[STEP01][PROVIDER ]   [2] SUN v21.0
[STEP01][INIT     ] Output directory prepare kar rahe hain...
[STEP01][DIR      ] cert/ directory create ki gayi: C:\pqc-demo\cert
[STEP01][KEYGEN   ] RSA-2048 key pair generate karna shuru...
[STEP01][KEYGEN   ] KeyPairGenerator instance le rahe hain — Algorithm: RSA, Provider: BC
[STEP01][KEYGEN   ] Key size initialize kar rahe hain: 2048 bits
[STEP01][KEYGEN   ] SecureRandom source: OS entropy (CryptGenRandom/urandom)
[STEP01][KEYGEN   ] Prime generation shuru... (p aur q dono ~1024-bit primes)
[STEP01][KEYGEN   ] Key pair generate hua in 214 ms
[STEP01][KEYGEN   ] Public key class : BCRSAPublicKey
[STEP01][KEYGEN   ] Private key class: BCRSACrtPrivateKey
[STEP01][INSPECT  ] Key pair ki details inspect kar rahe hain...
[STEP01][PUBKEY   ] Algorithm           : RSA
[STEP01][PUBKEY   ] Encoding Format     : X.509 (SubjectPublicKeyInfo ASN.1)
[STEP01][PUBKEY   ] Encoded Size        : 294 bytes (DER)
[STEP01][PUBKEY   ] Modulus Bit Length  : 2048 bits → RSA-2048 confirmed
[STEP01][PUBKEY   ] Public Exponent (e) : 65537 (Fermat prime F4, standard)
[STEP01][INSPECT  ] Private key ki internal structure dekh rahe hain...
[STEP01][PRIVKEY  ] Algorithm           : RSA
[STEP01][PRIVKEY  ] Encoding Format     : PKCS#8 PrivateKeyInfo (ASN.1)
[STEP01][PRIVKEY  ] Encoded Size        : 1218 bytes (DER)
[STEP01][PRIVKEY  ] Modulus (n) bits    : 2048 bits
[STEP01][PRIVKEY  ] Private Exponent (d): [HIDDEN — never log in production!]
[STEP01][PRIVKEY  ] CRT Prime p bits    : 1024 bits
[STEP01][PRIVKEY  ] CRT Prime q bits    : 1024 bits
[STEP01][PRIVKEY  ] CRT dp (d mod p-1)  : 1023 bits
[STEP01][PRIVKEY  ] CRT dq (d mod q-1)  : 1024 bits
[STEP01][PRIVKEY  ] CRT qInv (q⁻¹ mod p): 1023 bits
[STEP01][PRIVKEY  ] WHY CRT? → TLS handshake 4x faster with CRT vs naive RSA
[STEP01][PRIVKEY  ] WARNING : Private key SIRF server ke paas rehni chahiye!
[STEP01][SAVE     ] Private key DER encoded size: 1218 bytes
[STEP01][SAVE     ] Private key saved → C:\pqc-demo\cert\server.key.pem
[STEP01][SAVE     ] File size         : 1700 bytes
[STEP01][SAVE     ] PEM header        : -----BEGIN PRIVATE KEY----- (PKCS#8 format)
[STEP01][SAVE     ] WARNING           : Yeh file NEVER git commit karein!
[STEP01][SAVE     ] Public key DER encoded size: 294 bytes
[STEP01][SAVE     ] Public key saved  → C:\pqc-demo\cert\server.pub.pem
[STEP01][SAVE     ] File size         : 450 bytes
[STEP01][VERIFY   ] cert/server.key.pem → exists=true, size=1700 bytes ✓
[STEP01][VERIFY   ] cert/server.pub.pem → exists=true, size=450 bytes ✓
[STEP01][STORE    ] TlsCertStore mein key pair store kar rahe hain (Step02 ke liye)...
[STEP01][DONE     ] Step 01 Complete! Next → Step02_CsrGeneration.java

╔══════════════════════════════════════════════════════════════╗
║           STEP 01 SUMMARY — Server Key Pair                 ║
╠══════════════════════════════════════════════════════════════╣
║  Algorithm   : RSA                                          ║
║  Key Size    : 2048 bits                                    ║
║  Exponent    : 65537                                        ║
║  Pub Format  : X.509 SubjectPublicKeyInfo (PEM)             ║
║  Priv Format : PKCS#8 PrivateKeyInfo (PEM)                  ║
║  Saved       : cert/server.key.pem                          ║
║  Saved       : cert/server.pub.pem                          ║
╠══════════════════════════════════════════════════════════════╣
║  Next Step   : Step02_CsrGeneration.java                    ║
║  → CSR banayenge with maximum granular attributes           ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Security Checklist

| Item | Status | Note |
|---|---|---|
| Private key printed to console? | NO | Sirf metadata log hota hai |
| Private key in git? | NO | cert/ folder .gitignore mein hona chahiye |
| Key size adequate? | YES | RSA-2048, valid through 2030 |
| Provider explicit? | YES | "BC" explicitly specify kiya |
| SecureRandom used? | YES | OS entropy source |
| Production grade? | PARTIAL | Unencrypted PEM → production mein passphrase-encrypt karo |

---

## Next Step

**Step 02 → CSR Generation**

Is step ke baad `TlsCertStore.serverKeyPair` set ho gayi hai.  
Step02 is key pair ka use karke **PKCS#10 CSR** banayega with:
- Maximum granular Subject DN (8+ fields)
- Multiple SAN entries (DNS + IP)
- KeyUsage, ExtendedKeyUsage extensions
- SubjectKeyIdentifier
- BasicConstraints (isCA=false)
