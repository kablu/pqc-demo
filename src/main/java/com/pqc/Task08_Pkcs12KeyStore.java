package com.pqc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * =========================================================================
 * Task 08 — PKCS#12 KeyStore (Secure Key + Certificate Bundle)
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * PKCS#12 (RFC 7292, file extension .p12 or .pfx) ek password-protected
 * binary format hai jo private key + certificate + certificate chain
 * ek saath bundle karta hai. Java applications, browsers, Windows, macOS —
 * sab PKCS#12 format support karte hain. PKI deployment mein yeh
 * the MOST COMMON way to package and transfer key material.
 * </p>
 *
 * <h2>PKCS#12 Kyun Use Hota Hai?</h2>
 * <ul>
 *   <li><b>Spring Boot TLS</b> — `server.ssl.key-store=classpath:server.p12`</li>
 *   <li><b>mTLS Client Cert</b> — client proves identity with .p12 file</li>
 *   <li><b>Key Backup</b> — HSM key ceremony backup in encrypted .p12</li>
 *   <li><b>Browser Import</b> — personal certs imported as .p12 into Chrome/Firefox</li>
 *   <li><b>Java KeyStore</b> — `KeyStore.getInstance("PKCS12")` loads .p12 directly</li>
 * </ul>
 *
 * <h2>PKCS#12 Internal Structure</h2>
 * <pre>
 * PFX {
 *   AuthenticatedSafe {
 *     SafeContents [0] = ENCRYPTED_DATA {
 *       SafeBag (KeyBag or PKCS8ShroudedKeyBag) = private key (AES-256 encrypted)
 *     }
 *     SafeContents [1] = DATA {
 *       SafeBag (CertBag) = entity certificate
 *       SafeBag (CertBag) = CA certificate (chain)
 *     }
 *   }
 *   MacData = HMAC-SHA256 over AuthenticatedSafe (integrity check)
 * }
 * </pre>
 *
 * <h2>Security Evolution of PKCS#12</h2>
 * <pre>
 * Legacy (avoid!)   : RC2-40, RC2-128, 3DES — weak, deprecated
 * Modern (Java 8+)  : AES-128-CBC — acceptable
 * Strong (Java 17+) : AES-256-CBC + SHA-256 MAC — recommended
 * FIPS recommended  : AES-256-GCM (BouncyCastle FIPS mode)
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task08_Pkcs12KeyStore</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class Task08_Pkcs12KeyStore {

    /**
     * PKCS#12 protection password.
     *
     * <p><b>WHY char[] instead of String?</b><br>
     * Java {@link String} is immutable and stays in memory until GC.
     * {@code char[]} can be explicitly zeroed with {@code Arrays.fill(pass, '\0')}
     * after use. For passwords protecting cryptographic keys, this matters.
     * JCA APIs take char[] precisely for this reason.</p>
     *
     * <p><b>In production:</b> Password comes from HashiCorp Vault, never hardcoded.</p>
     */
    private static final char[] KEYSTORE_PASSWORD = "PQC-Demo-2026!@#".toCharArray();

    /**
     * Alias for the private key + certificate entry inside the keystore.
     *
     * <p>WHY alias? A single PKCS#12 can hold MULTIPLE key+cert pairs, each
     * identified by alias. TLS configuration references the alias:
     * {@code server.ssl.key-alias=ra-server}</p>
     */
    private static final String KEY_ALIAS = "ra-server-key";

    /**
     * Alias for the trusted CA certificate entry.
     *
     * <p>WHY separate alias for CA cert? Keystores hold two types of entries:
     * (1) KeyEntry = private key + cert chain (for MY identity)
     * (2) TrustedCertEntry = just a cert (for trusting others — trust store)
     * Same PKCS#12 can serve as both a key store and a trust store.</p>
     */
    private static final String CA_ALIAS = "pqc-root-ca";

    /**
     * Entry point — creates, saves, and reloads a PKCS#12 keystore.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if keystore operations fail
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 08 — PKCS#12 KeyStore Creation & Loading");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        if (CertificateStore.entityCert == null) {
            Task04_IssueCertFromCsr.main(new String[]{});
        }

        // Step 1: Create and populate a PKCS#12 keystore
        KeyStore keyStore = createPkcs12KeyStore(
            CertificateStore.entityKeyPair.getPrivate(),
            new X509Certificate[]{
                CertificateStore.entityCert,  // entity cert at [0]
                CertificateStore.caCert        // CA cert for chain at [1]
            }
        );

        // Step 2: Add trusted CA certificate (trust store entry)
        addTrustedCaCert(keyStore, CertificateStore.caCert, CA_ALIAS);

        // Step 3: Inspect the keystore contents
        listKeystoreContents(keyStore);

        // Step 4: Save keystore to file (.p12)
        String p12FilePath = "ra-server.p12";
        saveKeystoreToFile(keyStore, p12FilePath);

        // Step 5: Reload the keystore from file (simulate Spring Boot loading)
        KeyStore reloaded = loadKeystoreFromFile(p12FilePath);

        // Step 6: Retrieve private key and cert from loaded keystore
        retrieveAndVerifyKeyEntry(reloaded);

        // Step 7: Show how Spring Boot would use this .p12
        printSpringBootConfig(p12FilePath);

        System.out.println("✅ Task 08 Complete — PKCS#12 KeyStore mastered!");
        System.out.println("\n🎉 ALL 8 TASKS COMPLETE! You've mastered BC fundamentals.");
        System.out.println("   Next Phase: PQC — Task ML-KEM + ML-DSA with JEP 496/497");
    }

    // =========================================================================
    // Step 1 — Create and Populate PKCS#12 KeyStore
    // =========================================================================

    /**
     * Creates a PKCS#12 keystore and stores the private key with certificate chain.
     *
     * <p><b>WHY PKCS12 KeyStore type?</b><br>
     * Java supports multiple keystore types:
     * <ul>
     *   <li>{@code PKCS12} — standard, portable, supported everywhere (recommended)</li>
     *   <li>{@code JKS} — Java-only legacy format, avoid for new code</li>
     *   <li>{@code PKCS11} — hardware keystore (HSM via SunPKCS11)</li>
     *   <li>{@code BKS} — BouncyCastle format for Android</li>
     * </ul>
     * PKCS12 is the default since Java 9 (JEP 229). Use it exclusively.</p>
     *
     * <p><b>Certificate chain order — WHY matters?</b><br>
     * chain[0] MUST be the entity's own cert. chain[1] = issuing CA.
     * chain[n-1] = root CA. Verifiers walk the chain from [0] up.
     * Wrong order causes TLS handshake failures.</p>
     *
     * <p><b>Key protection — WHY password?</b><br>
     * The private key inside PKCS#12 is encrypted with AES-256-CBC
     * derived from the password via PBKDF2. Without the password, the
     * encrypted bytes are useless — this protects the key at rest.</p>
     *
     * @param privateKey the entity's private key to store
     * @param certChain  certificate chain: [0]=entity cert, [1..n]=CA chain
     * @return the populated {@link KeyStore}
     * @throws Exception if keystore creation fails
     */
    public static KeyStore createPkcs12KeyStore(PrivateKey privateKey,
                                                 X509Certificate[] certChain) throws Exception {
        System.out.println("🏗️  Creating PKCS#12 KeyStore...");

        // KeyStore.getInstance("PKCS12") — load PKCS#12 format implementation
        // "BC" provider: BouncyCastle PKCS#12 supports AES-256 encryption (stronger than JDK default)
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

        // load(null, null) — initialize a NEW empty keystore (no input stream, no password)
        // WHY null? We're creating from scratch, not loading from file.
        ks.load(null, null);

        // ---- Store Private Key Entry ----
        // setKeyEntry(alias, key, password, certChain)
        // alias: identifies this entry — used in TLS config `key-alias`
        // password: protects the private key encryption inside PKCS#12
        // certChain: must include entity cert + full chain up to root
        ks.setKeyEntry(
            KEY_ALIAS,          // entry identifier
            privateKey,         // RSA-4096 private key
            KEYSTORE_PASSWORD,  // key encryption password
            certChain           // [entity cert, CA cert]
        );

        System.out.println("   ✔ Private key stored under alias: '" + KEY_ALIAS + "'");
        System.out.printf( "   ✔ Certificate chain length: %d%n", certChain.length);
        return ks;
    }

    // =========================================================================
    // Step 2 — Add Trusted CA Certificate
    // =========================================================================

    /**
     * Adds a trusted CA certificate to the keystore as a TrustedCertificateEntry.
     *
     * <p><b>TrustedCertEntry vs KeyEntry:</b><br>
     * KeyEntry = has private key — "I am this entity"
     * TrustedCertEntry = only has cert — "I trust this CA"
     * A single PKCS#12 can serve as BOTH a keystore (for client auth)
     * AND a trust store (for CA trust), which is how Spring Boot mTLS uses it.</p>
     *
     * <p><b>In Spring Boot mTLS config:</b>
     * <pre>
     * server.ssl.key-store      = same .p12 (for server's own cert)
     * server.ssl.trust-store    = same .p12 (trusted CAs for client cert validation)
     * server.ssl.client-auth    = NEED (require mTLS)
     * </pre>
     * </p>
     *
     * @param keyStore the keystore to add the CA cert to
     * @param caCert   the CA certificate to trust
     * @param alias    the alias for this trusted cert entry
     * @throws Exception if cert entry storage fails
     */
    public static void addTrustedCaCert(KeyStore keyStore,
                                         X509Certificate caCert,
                                         String alias) throws Exception {
        // setCertificateEntry(alias, cert) stores a trusted cert (no private key)
        // This is how you configure "I trust this CA" in a Java keystore
        keyStore.setCertificateEntry(alias, caCert);
        System.out.println("   ✔ Trusted CA cert stored under alias: '" + alias + "'");
        System.out.println();
    }

    // =========================================================================
    // Step 3 — Inspect KeyStore Contents
    // =========================================================================

    /**
     * Lists all entries in the keystore with their types and details.
     *
     * <p><b>WHY inspect?</b><br>
     * In production, verifying keystore contents before deploying to a server
     * prevents misconfigurations. Common mistake: wrong alias in Spring Boot
     * config causes 'UnrecoverableKeyException' at startup. Also useful for
     * auditing what keys are in a PKCS#12 bundle.</p>
     *
     * <p><b>Equivalent CLI command:</b><br>
     * {@code keytool -list -v -keystore server.p12 -storetype PKCS12}</p>
     *
     * @param keyStore the keystore to inspect
     * @throws Exception if keystore access fails
     */
    public static void listKeystoreContents(KeyStore keyStore) throws Exception {
        System.out.println("📋 KeyStore Contents:");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");
        System.out.println("   │ Type    : " + keyStore.getType());
        System.out.println("   │ Provider: " + keyStore.getProvider().getName());
        System.out.printf( "   │ Entries : %d%n", keyStore.size());
        System.out.println("   │──────────────────────────────────────────────────────│");

        // aliases() returns all entry aliases in the keystore
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            // isKeyEntry(alias) = true if this entry has a private key
            if (keyStore.isKeyEntry(alias)) {
                Certificate cert = keyStore.getCertificate(alias);
                X509Certificate x509 = (X509Certificate) cert;

                System.out.println("   │ [KEY ENTRY]");
                System.out.println("   │   Alias    : " + alias);
                System.out.println("   │   Subject  : " + x509.getSubjectX500Principal().getName());
                System.out.println("   │   Issuer   : " + x509.getIssuerX500Principal().getName());
                System.out.println("   │   Serial   : 0x" + x509.getSerialNumber().toString(16));
                System.out.println("   │   Expires  : " + x509.getNotAfter());

                // getKey(alias, password) — retrieve private key (requires password)
                java.security.Key key = keyStore.getKey(alias, KEYSTORE_PASSWORD);
                System.out.println("   │   Key Algo : " + key.getAlgorithm());

                // Chain length — should be 2 (entity + CA)
                Certificate[] chain = keyStore.getCertificateChain(alias);
                System.out.println("   │   Chain Len: " + (chain != null ? chain.length : 0));

            } else if (keyStore.isCertificateEntry(alias)) {
                // isCertificateEntry(alias) = true if this is just a trusted cert (no private key)
                X509Certificate caCert = (X509Certificate) keyStore.getCertificate(alias);

                System.out.println("   │ [TRUSTED CERT ENTRY]");
                System.out.println("   │   Alias    : " + alias);
                System.out.println("   │   Subject  : " + caCert.getSubjectX500Principal().getName());
                System.out.println("   │   IsCA     : " + (caCert.getBasicConstraints() >= 0 ? "YES" : "NO"));
            }

            System.out.println("   │──────────────────────────────────────────────────────│");
        }
        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 4 — Save Keystore to File
    // =========================================================================

    /**
     * Serializes the keystore to a .p12 file on disk.
     *
     * <p><b>WHY store to file?</b><br>
     * Spring Boot reads the PKCS#12 file at startup via {@code server.ssl.key-store}.
     * DevOps deploys it as a Kubernetes Secret or mounts it from a Vault PKI engine.
     * The file must be protected with OS file permissions (chmod 600 on Linux).</p>
     *
     * <p><b>Password for store() call:</b><br>
     * The PKCS#12 store password protects the MAC (message authentication code)
     * that verifies the entire PKCS#12 wasn't tampered. Individual keys have their
     * own password (set in setKeyEntry). In Java's PKCS12 implementation, both
     * passwords are typically the same.</p>
     *
     * @param keyStore   the keystore to save
     * @param filePath   the output .p12 file path
     * @throws Exception if I/O or serialization fails
     */
    public static void saveKeystoreToFile(KeyStore keyStore, String filePath) throws Exception {
        System.out.println("💾 Saving PKCS#12 to: " + filePath);

        // store(outputStream, password)
        // password: used to compute HMAC-SHA256 over the entire keystore (integrity check)
        // Write directly to file — avoids doubling peak memory via an intermediate byte[]
        try (java.io.OutputStream out = new java.io.BufferedOutputStream(
                new FileOutputStream(filePath))) {
            keyStore.store(out, KEYSTORE_PASSWORD);
        }

        System.out.printf("   ✔ Saved %d bytes → %s%n%n", Files.size(Paths.get(filePath)), filePath);
    }

    // =========================================================================
    // Step 5 — Reload KeyStore from File
    // =========================================================================

    /**
     * Loads a PKCS#12 keystore from a file — exactly how Spring Boot does it.
     *
     * <p><b>This is the MOST IMPORTANT method to understand:</b><br>
     * Spring Boot's TLS auto-configuration calls this internally when you set:
     * {@code server.ssl.key-store=file:ra-server.p12}
     * Understanding this helps debug TLS configuration issues in production.</p>
     *
     * @param filePath path to the .p12 file
     * @return loaded {@link KeyStore}
     * @throws Exception if file is not found, password is wrong, or format is corrupt
     */
    public static KeyStore loadKeystoreFromFile(String filePath) throws Exception {
        System.out.println("📂 Loading PKCS#12 from: " + filePath);

        // Create a new PKCS12 keystore instance
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

        // load(inputStream, password) — deserializes and integrity-checks the .p12
        // password: used to verify the HMAC-SHA256 integrity check.
        // If password is wrong → UnrecoverableKeyException
        // If file is corrupted → IOException / KeyStoreException
        // Stream directly from file — avoids loading the entire .p12 into a byte[]
        try (java.io.InputStream in = new java.io.BufferedInputStream(
                Files.newInputStream(Paths.get(filePath)))) {
            ks.load(in, KEYSTORE_PASSWORD);
        }

        System.out.printf("   ✔ Loaded PKCS#12 successfully — %d entries found%n%n", ks.size());
        return ks;
    }

    // =========================================================================
    // Step 6 — Retrieve and Verify Key Entry
    // =========================================================================

    /**
     * Retrieves the private key and certificate from the loaded keystore and verifies consistency.
     *
     * <p><b>Consistency check — WHY?</b><br>
     * After loading from file, verify that:
     * (1) Private key modulus matches the public key in the certificate
     * (2) Certificate chain is complete and correctly ordered
     * This catches common mistakes: wrong cert imported, key-cert mismatch,
     * incomplete chain — all of which cause TLS handshake failures.</p>
     *
     * @param keyStore the loaded keystore to retrieve from
     * @throws Exception if key retrieval or verification fails
     */
    public static void retrieveAndVerifyKeyEntry(KeyStore keyStore) throws Exception {
        System.out.println("🔑 Retrieving and verifying key entry...");

        // getKey(alias, password) — returns the PrivateKey
        // If password is wrong → UnrecoverableKeyException (key decryption failed)
        PrivateKey retrievedKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD);

        // getCertificate(alias) — returns the entity's X.509 cert
        X509Certificate retrievedCert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);

        // getCertificateChain(alias) — returns full chain [entity, CA, ...]
        Certificate[] chain = keyStore.getCertificateChain(KEY_ALIAS);

        System.out.println("   ✔ Private Key Algorithm : " + retrievedKey.getAlgorithm());
        System.out.println("   ✔ Certificate Subject   : " +
            retrievedCert.getSubjectX500Principal().getName());
        System.out.println("   ✔ Certificate Chain Len : " + chain.length);

        // Consistency check: public key in cert must match the private key
        // RSA: compare modulus of cert's public key with private key's modulus
        java.security.interfaces.RSAPrivateCrtKey rsaPrivate =
            (java.security.interfaces.RSAPrivateCrtKey) retrievedKey;
        java.security.interfaces.RSAPublicKey rsaPublic =
            (java.security.interfaces.RSAPublicKey) retrievedCert.getPublicKey();

        // WHY compare modulus? RSA keypair: both keys share the SAME modulus (n = p × q).
        // If moduli match → private key and cert are from the same key pair.
        // If they don't match → someone put the wrong cert with this private key!
        boolean consistent = rsaPrivate.getModulus().equals(rsaPublic.getModulus());
        System.out.println("   " + (consistent
            ? "✅ Key-Cert consistency: MATCH — private key matches the certificate!"
            : "❌ Key-Cert consistency: MISMATCH — wrong cert for this private key!"));
        System.out.println();
    }

    // =========================================================================
    // Step 7 — Spring Boot Configuration Reference
    // =========================================================================

    /**
     * Prints the Spring Boot application.properties configuration for using this .p12 file.
     *
     * <p><b>WHY show config?</b><br>
     * RA system ka Spring Boot TLS endpoint yahi configuration use karta hai.
     * Understanding the connection between keystore and config prevents
     * deployment mistakes that cause certificate errors in production.</p>
     *
     * @param p12FilePath path to the generated .p12 file
     */
    public static void printSpringBootConfig(String p12FilePath) {
        System.out.println("⚙️  Spring Boot TLS Configuration (application.properties):");
        System.out.println("   ─────────────────────────────────────────────────────────");
        System.out.println("   # HTTPS with this PKCS#12 keystore:");
        System.out.println("   server.port=8443");
        System.out.println("   server.ssl.enabled=true");
        System.out.println("   server.ssl.key-store=file:" + p12FilePath);
        System.out.println("   server.ssl.key-store-type=PKCS12");
        System.out.println("   server.ssl.key-store-password=<keystore-password>");
        System.out.println("   server.ssl.key-alias=" + KEY_ALIAS);
        System.out.println();
        System.out.println("   # For mTLS (require client certificates):");
        System.out.println("   server.ssl.client-auth=NEED");
        System.out.println("   server.ssl.trust-store=file:" + p12FilePath);
        System.out.println("   server.ssl.trust-store-type=PKCS12");
        System.out.println("   server.ssl.trust-store-password=<keystore-password>");
        System.out.println("   ─────────────────────────────────────────────────────────\n");
    }
}
