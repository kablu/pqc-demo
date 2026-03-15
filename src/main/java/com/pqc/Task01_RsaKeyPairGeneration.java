package com.pqc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

/**
 * =========================================================================
 * Task 01 — RSA Key Pair Generation using BouncyCastle
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * RSA key pair generation PQC journey ka FIRST step hai. RSA classic
 * asymmetric cryptography ka backbone hai — isko solid samjho, tab
 * ML-KEM (quantum-safe alternative) se compare karna aasaan ho jaayega.
 * </p>
 *
 * <h2>Concept in Simple Words</h2>
 * <ul>
 *   <li><b>Public Key</b>  — sabko de sakte ho. Encrypt / Verify karta hai.</li>
 *   <li><b>Private Key</b> — sirf tumhare paas. Decrypt / Sign karta hai.</li>
 *   <li><b>Key Size 4096</b> — RSA mein security = key size. 2048 minimum,
 *       4096 recommended for PKI/RA use where keys live for years.</li>
 * </ul>
 *
 * <h2>Why RSA is Quantum-Vulnerable</h2>
 * <p>
 * RSA security depend karta hai on "integer factorization problem" —
 * bade numbers ko factor karna classical computer ke liye bahut mushkil hai.
 * Lekin Shor's algorithm on a quantum computer isko polynomial time mein
 * solve kar sakta hai. Isliye hum PQC (ML-KEM, ML-DSA) seekh rahe hain.
 * </p>
 *
 * <h2>BouncyCastle vs JDK Built-in</h2>
 * <p>
 * JDK bhi RSA support karta hai, lekin BouncyCastle use karte hain kyunki:
 * (1) BC PQC algorithms support karta hai (ML-KEM, ML-DSA) — JDK 24 tak wait nahi
 * (2) BC FIPS-validated library hai — PKI/RA production use ke liye zaroori
 * (3) BC mein X.509, CRL, OCSP, CMP sab ek jagah milta hai
 * </p>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task01_RsaKeyPairGeneration</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class Task01_RsaKeyPairGeneration {

    /**
     * RSA key size in bits.
     *
     * <p>WHY 4096? RSA-2048 is minimum but expires ~2030 per NIST recommendation.
     * For RA system where certificates are valid 1-5 years, we use 4096
     * to ensure the SIGNING key outlasts all issued certificates.</p>
     */
    private static final int RSA_KEY_SIZE = 4096;

    /**
     * Algorithm name used with JCE KeyPairGenerator.
     *
     * <p>WHY "RSA"? Java Cryptography Architecture (JCA) uses string-based
     * algorithm names. "RSA" maps to RSA-PKCS#1 key pair. BouncyCastle
     * provider intercepts this and uses its own optimized RSA implementation.</p>
     */
    private static final String ALGORITHM = "RSA";

    /**
     * Entry point — demonstrates full RSA key generation lifecycle.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if key generation or encoding fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 01 — RSA Key Pair Generation with BouncyCastle");
        System.out.println("=============================================================\n");

        registerBouncyCastleProvider();

        KeyPair keyPair = generateRsaKeyPair();

        printKeyDetails(keyPair);

        printPemEncoded(keyPair);

        demonstrateKeyUsage(keyPair);

        System.out.println("\n✅ Task 01 Complete — RSA Key Pair generated successfully!");
        System.out.println("   Next Step → Task02_SelfSignedCaCertificate.java");
    }

    // =========================================================================
    // Step 1 — Register BouncyCastle as JCE Security Provider
    // =========================================================================

    /**
     * Registers BouncyCastle as a JCE (Java Cryptography Extension) provider.
     *
     * <p><b>WHY register a provider?</b><br>
     * Java's JCA/JCE is a pluggable framework. By default, JDK has SunRsaSign,
     * SunEC providers. BouncyCastle is an ADDITIONAL provider that gives us:
     * <ul>
     *   <li>ML-KEM, ML-DSA (PQC algorithms not in JDK 21)</li>
     *   <li>PKCS#11, PKCS#12 advanced support</li>
     *   <li>FIPS 140-2 validated algorithms</li>
     * </ul>
     * </p>
     *
     * <p><b>WHY insertProviderAt(..., 1)?</b><br>
     * Position 1 means HIGHEST priority. When we call
     * {@code KeyPairGenerator.getInstance("RSA")}, JVM searches providers
     * from position 1 upward. Position 1 ensures BouncyCastle is always
     * picked first over the default Sun providers.</p>
     *
     * <p><b>Idempotent?</b> Yes — if BC is already registered, this is a no-op.
     * Safe to call multiple times.</p>
     */
    public static void registerBouncyCastleProvider() {

        // Check if BouncyCastle is already registered to avoid duplicate registration.
        // Security.getProvider() returns null if provider not found.
        if (Security.getProvider("BC") == null) {

            // Insert BouncyCastle at position 1 (highest priority).
            // new BouncyCastleProvider() loads all BC algorithm implementations.
            Security.insertProviderAt(new BouncyCastleProvider(), 1);

            System.out.println("✔ BouncyCastle Provider registered at position 1");
        } else {
            System.out.println("✔ BouncyCastle Provider already registered — skipping");
        }

        // Print all registered providers for transparency in learning
        System.out.println("\n📋 Registered JCE Providers:");
        for (java.security.Provider p : Security.getProviders()) {
            System.out.printf("   [%d] %s v%.1f%n",
                java.util.Arrays.asList(Security.getProviders()).indexOf(p) + 1,
                p.getName(),
                p.getVersion());
        }
        System.out.println();
    }

    // =========================================================================
    // Step 2 — Generate RSA Key Pair
    // =========================================================================

    /**
     * Generates an RSA-4096 key pair using BouncyCastle provider.
     *
     * <p><b>WHY KeyPairGenerator?</b><br>
     * Java's {@code KeyPairGenerator} is the standard JCE API for generating
     * asymmetric key pairs. It abstracts away algorithm-specific math (prime
     * generation, modular exponentiation) behind a clean interface. We pass
     * the algorithm name ("RSA") and key size, and JCE handles the rest.</p>
     *
     * <p><b>How RSA key generation works (simplified):</b>
     * <ol>
     *   <li>Generate two random large primes: p and q (each ~2048 bits)</li>
     *   <li>Compute modulus: n = p × q (this is the 4096-bit RSA modulus)</li>
     *   <li>Public key  = (n, e) where e = 65537 (standard public exponent)</li>
     *   <li>Private key = (n, d) where d = modular inverse of e mod λ(n)</li>
     * </ol>
     * Security comes from: knowing n but not being able to factor it back to p, q.
     * </p>
     *
     * <p><b>WHY 65537 as public exponent?</b><br>
     * e = 65537 = 2^16 + 1 in binary is 10000000000000001 — only two 1-bits,
     * making modular exponentiation very fast for encryption/verification.</p>
     *
     * @return generated {@link KeyPair} containing RSA public + private key
     * @throws Exception if the algorithm is not available or key size is invalid
     */
    public static KeyPair generateRsaKeyPair() throws Exception {
        System.out.println("🔑 Generating RSA-" + RSA_KEY_SIZE + " Key Pair...");
        System.out.println("   (This may take 1-3 seconds — large prime generation)");

        long startMs = System.currentTimeMillis();

        // Get a KeyPairGenerator instance for RSA algorithm.
        // "BC" explicitly requests BouncyCastle provider — ensures we use BC's RSA,
        // not Sun's. Important when running alongside FIPS providers.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, "BC");

        // Initialize the generator with key size.
        // WHY no SecureRandom argument? KeyPairGenerator.initialize() will
        // automatically use SecureRandom.getInstanceStrong() — the strongest
        // available source (e.g., /dev/random on Linux, CryptGenRandom on Windows).
        keyGen.initialize(RSA_KEY_SIZE);

        // generateKeyPair() performs the actual prime generation and math.
        // This is CPU-intensive for 4096-bit — normal on modern hardware is 1-3s.
        KeyPair keyPair = keyGen.generateKeyPair();

        long elapsed = System.currentTimeMillis() - startMs;
        System.out.printf("✔ RSA-%d Key Pair generated in %d ms%n%n", RSA_KEY_SIZE, elapsed);

        return keyPair;
    }

    // =========================================================================
    // Step 3 — Inspect Key Details
    // =========================================================================

    /**
     * Prints the key algorithm, format, and encoded size for learning purposes.
     *
     * <p><b>WHY inspect key details?</b><br>
     * Understanding the internal structure of a key is crucial for PKI work.
     * You need to know: What algorithm? What encoding format? How big? These
     * properties determine compatibility with HSMs, TLS, X.509 certificates.</p>
     *
     * <p><b>Key encoding formats explained:</b>
     * <ul>
     *   <li><b>X.509 (SubjectPublicKeyInfo)</b> — standard public key encoding
     *       used in certificates, TLS, CSRs. Defined in RFC 5480.</li>
     *   <li><b>PKCS#8 (PrivateKeyInfo)</b> — standard private key encoding.
     *       Wraps the raw key in a structure that includes algorithm identifier.
     *       Used in PEM files, PKCS#12 keystores.</li>
     * </ul>
     * </p>
     *
     * @param keyPair the RSA key pair to inspect
     */
    public static void printKeyDetails(KeyPair keyPair) {
        PublicKey  publicKey  = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("📊 Key Details:");
        System.out.println("   ┌─────────────────────────────────────────────────┐");

        // getAlgorithm() returns "RSA" — confirms the algorithm
        System.out.println("   │ Algorithm   : " + publicKey.getAlgorithm());

        // getFormat() for RSA public key returns "X.509" (SubjectPublicKeyInfo ASN.1 structure)
        // WHY X.509? Because this is the standard format used in X.509 certificates
        System.out.println("   │ Public Key Format  : " + publicKey.getFormat());

        // PKCS#8 is the standard private key format — wraps raw key data with
        // algorithm identifier. This is what gets stored in PEM files and keystores.
        System.out.println("   │ Private Key Format : " + privateKey.getFormat());

        // getEncoded() returns DER-encoded bytes. Length tells us key size.
        // RSA-4096 public key DER ≈ 550 bytes, private key ≈ 2350 bytes
        System.out.printf( "   │ Public Key Size    : %d bytes (DER encoded)%n",
            publicKey.getEncoded().length);
        System.out.printf( "   │ Private Key Size   : %d bytes (DER encoded)%n",
            privateKey.getEncoded().length);

        // Cast to RSAPublicKey to access RSA-specific modulus details
        java.security.interfaces.RSAPublicKey rsaPublicKey =
            (java.security.interfaces.RSAPublicKey) publicKey;

        // getModulus().bitLength() gives the actual RSA key bit size — should be 4096
        System.out.printf( "   │ Modulus Bit Length : %d bits%n",
            rsaPublicKey.getModulus().bitLength());

        // getPublicExponent() should be 65537 (Fermat prime F4) for standard RSA keys
        System.out.println("   │ Public Exponent    : " + rsaPublicKey.getPublicExponent());

        System.out.println("   └─────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Step 4 — PEM Encoding (How Keys Are Stored in Files)
    // =========================================================================

    /**
     * Prints the public and private keys in PEM (Base64) format.
     *
     * <p><b>WHY PEM format?</b><br>
     * PEM (Privacy-Enhanced Mail) is the most common way to store cryptographic
     * objects as text. It Base64-encodes DER bytes and wraps with
     * {@code -----BEGIN/END-----} markers. Almost every PKI tool (openssl,
     * keytool, EJBCA, NGINX) understands PEM. Real files have .pem, .key, .crt
     * extensions.</p>
     *
     * <p><b>⚠️ WARNING — In production NEVER print/log private keys!</b><br>
     * This is ONLY for learning purposes. Private keys must be:
     * (1) Stored in HSM (never exported), OR
     * (2) Stored in encrypted PKCS#12 keystore, OR
     * (3) Stored in encrypted PEM with AES-256 passphrase.</p>
     *
     * @param keyPair the key pair to encode and print
     */
    public static void printPemEncoded(KeyPair keyPair) {
        System.out.println("📄 PEM Encoded Keys (Base64 DER encoding):");

        // ---- Public Key PEM ----
        // getEncoded() returns DER bytes (binary). Base64.getMimeEncoder(64, "\n".getBytes())
        // converts to Base64 with 64-char line wrapping — standard PEM line length.
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(keyPair.getPublic().getEncoded())
            + "\n-----END PUBLIC KEY-----";

        System.out.println(publicKeyPem);
        System.out.println();

        // ---- Private Key PEM ----
        // PKCS#8 DER bytes encoded as PEM.
        // "BEGIN PRIVATE KEY" = unencrypted PKCS#8 (standard)
        // "BEGIN RSA PRIVATE KEY" = legacy PKCS#1 format — avoid for new code
        // "BEGIN ENCRYPTED PRIVATE KEY" = passphrase-protected PKCS#8 (production)
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(keyPair.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----";

        // Print only first 200 chars — private key is very long (4096-bit)
        // In real code: write to encrypted file, not console
        System.out.println("-----BEGIN PRIVATE KEY----- (truncated for safety)");
        System.out.println(privateKeyPem.substring(0, Math.min(200, privateKeyPem.length())) + "...");
        System.out.println("-----END PRIVATE KEY-----");
        System.out.println("⚠️  NEVER log full private keys in production!\n");
    }

    // =========================================================================
    // Step 5 — Demonstrate Basic Key Usage
    // =========================================================================

    /**
     * Demonstrates encryption with public key and decryption with private key.
     *
     * <p><b>WHY RSA encrypt/decrypt demo?</b><br>
     * This confirms the key pair is mathematically linked — data encrypted
     * with the public key can ONLY be decrypted with the corresponding
     * private key. This asymmetric property is the foundation of PKI trust.</p>
     *
     * <p><b>Important PKI note:</b><br>
     * In real PKI systems, RSA is NOT used to encrypt bulk data directly.
     * RSA is used to encrypt a SYMMETRIC key (e.g., AES-256) — this is
     * called "hybrid encryption". The symmetric key then encrypts the data.
     * This is exactly what TLS, CMS (PKCS#7), and ML-KEM do.</p>
     *
     * <p><b>Padding WHY RSA/ECB/OAEPWithSHA-256AndMGF1Padding?</b><br>
     * OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 is the
     * CURRENT STANDARD padding. Never use PKCS1Padding (legacy, vulnerable
     * to Bleichenbacher attack). OAEP adds randomness — same plaintext
     * encrypts to different ciphertext each time.</p>
     *
     * @param keyPair the RSA key pair to test
     * @throws Exception if encryption or decryption fails
     */
    public static void demonstrateKeyUsage(KeyPair keyPair) throws Exception {
        System.out.println("🔐 Key Usage Demonstration — Encrypt / Decrypt:");

        // The message we want to encrypt — simulating a small AES session key
        String originalMessage = "Hello PKI! This could be an AES-256 session key.";
        System.out.println("   Original  : " + originalMessage);

        // ---- ENCRYPT with Public Key ----
        // Cipher.getInstance(transformation, provider)
        // "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" is the transformation string:
        // - RSA    = algorithm
        // - ECB    = mode (for asymmetric ciphers, mode is irrelevant; ECB is a placeholder)
        // - OAEP   = padding scheme — secure, randomized, standard
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");

        // ENCRYPT_MODE: use PUBLIC key to encrypt — anyone can send encrypted data
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // doFinal() performs encryption. Output is RSA ciphertext bytes.
        // Length = RSA modulus size = 4096/8 = 512 bytes
        byte[] encrypted = cipher.doFinal(originalMessage.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.printf("   Encrypted : [%d bytes ciphertext — looks random]%n", encrypted.length);

        // ---- DECRYPT with Private Key ----
        // Only the private key holder can decrypt — ensures confidentiality
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        String decryptedMessage = new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("   Decrypted : " + decryptedMessage);

        // Verify decryption is perfect
        boolean success = originalMessage.equals(decryptedMessage);
        System.out.println("   Match     : " + (success ? "✅ YES — keys are correctly paired!" : "❌ NO — something is wrong!"));
        System.out.println();
    }
}
