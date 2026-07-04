package com.pqc.ca.tls;

import com.pqc.Task01_RsaKeyPairGeneration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * =========================================================================
 * Step 01 — TLS Server Key Pair Generation
 * =========================================================================
 *
 * <h2>Is Step Mein Kya Hoga?</h2>
 * <p>
 * TLS Server ke liye RSA-2048 key pair generate karenge. Yeh private key
 * server pe secret rehti hai — kabhi kisi ko share nahi hoti. Public key
 * CSR (Step02) ke andar jaayegi aur certificate mein embed hogi.
 * </p>
 *
 * <h2>Key Pair Kya Hota Hai?</h2>
 * <pre>
 * Private Key (server ke paas, secret):
 *   → TLS Handshake mein server apni identity PROVE karta hai
 *   → Client ka pre-master secret decrypt karta hai
 *   → NEVER share, NEVER log, NEVER transfer over network
 *
 * Public Key (certificate mein, sab dekh sakte hain):
 *   → Client encrypt karta hai public key se
 *   → Certificate mein embed hoti hai
 *   → CSR ke saath CA ko bheji jaati hai
 * </pre>
 *
 * <h2>Output Files</h2>
 * <pre>
 *   cert/server.key.pem  — PKCS#8 PEM format private key (unencrypted)
 *   cert/server.pub.pem  — Public key PEM format
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>.\gradlew.bat run -PmainClass=com.pqc.ca.tls.Step01_ServerKeyPairGeneration</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-07-04
 */
public class Step01_ServerKeyPairGeneration {

    /** RSA key size for TLS Server: 2048 bits */
    private static final int KEY_SIZE = 2048;

    /** Output directory for all generated files */
    private static final String CERT_DIR = "cert";

    /** Private key output file */
    private static final String PRIVATE_KEY_FILE = CERT_DIR + "/server.key.pem";

    /** Public key output file */
    private static final String PUBLIC_KEY_FILE = CERT_DIR + "/server.pub.pem";

    // =========================================================================
    // MAIN
    // =========================================================================

    public static void main(String[] args) throws Exception {

        printBanner();

        log("INIT", "Starting Step 01 — TLS Server Key Pair Generation");
        log("INIT", "BouncyCastle provider register kar rahe hain...");
        registerProvider();

        log("INIT", "Output directory prepare kar rahe hain...");
        prepareCertDirectory();

        log("KEYGEN", "RSA-" + KEY_SIZE + " key pair generate karna shuru...");
        KeyPair keyPair = generateServerKeyPair();

        log("INSPECT", "Key pair ki details inspect kar rahe hain...");
        inspectPublicKey(keyPair);

        log("INSPECT", "Private key ki internal structure dekh rahe hain...");
        inspectPrivateKey(keyPair);

        log("SAVE", "Private key PEM file mein save kar rahe hain...");
        String privateKeyPem = savePrivateKey(keyPair);

        log("SAVE", "Public key PEM file mein save kar rahe hain...");
        String publicKeyPem = savePublicKey(keyPair);

        log("VERIFY", "Save ki gayi files verify kar rahe hain...");
        verifyFilesWritten();

        log("STORE", "TlsCertStore mein key pair store kar rahe hain (Step02 ke liye)...");
        TlsCertStore.serverKeyPair = keyPair;

        printSummary(keyPair, privateKeyPem, publicKeyPem);

        log("DONE", "Step 01 Complete! Next → Step02_CsrGeneration.java");
    }

    // =========================================================================
    // Step 1A — BouncyCastle Provider Register
    // =========================================================================

    /**
     * BouncyCastle ko JCE provider ke roop mein register karta hai.
     *
     * <p><b>Kyu zaruri hai?</b><br>
     * Java ka default JDK provider RSA support karta hai, lekin BouncyCastle
     * use karte hain kyunki:
     * <ul>
     *   <li>BC PKCS#10 CSR generation support karta hai (Step02 mein chahiye)</li>
     *   <li>BC X.509 certificate building support karta hai (Step04 mein chahiye)</li>
     *   <li>BC PQC algorithms support karta hai (future steps ke liye)</li>
     * </ul>
     * </p>
     */
    private static void registerProvider() {
        if (Security.getProvider("BC") == null) {
            log("PROVIDER", "BouncyCastle provider NOT found — abhi register kar rahe hain");
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            log("PROVIDER", "BouncyCastle registered at position 1 (highest priority)");
        } else {
            log("PROVIDER", "BouncyCastle already registered — skip");
        }

        log("PROVIDER", "Active JCE providers:");
        int i = 1;
        for (java.security.Provider p : Security.getProviders()) {
            log("PROVIDER", "  [" + i++ + "] " + p.getName() + " v" + String.format("%.1f", p.getVersion()));
        }
    }

    // =========================================================================
    // Step 1B — Output Directory Prepare
    // =========================================================================

    /**
     * cert/ directory create karta hai agar exist nahi karta.
     *
     * <p><b>Kyu alag directory?</b><br>
     * Private keys, CSRs aur certificates ko source code se ALAG rakhna
     * best practice hai. .gitignore mein cert/ add karo — keys kabhi
     * GitHub pe nahi jaani chahiye.</p>
     */
    private static void prepareCertDirectory() throws IOException {
        Path certPath = Paths.get(CERT_DIR);
        if (!Files.exists(certPath)) {
            Files.createDirectories(certPath);
            log("DIR", "cert/ directory create ki gayi: " + certPath.toAbsolutePath());
        } else {
            log("DIR", "cert/ directory already exists: " + certPath.toAbsolutePath());
        }
    }

    // =========================================================================
    // Step 1C — Key Pair Generation
    // =========================================================================

    /**
     * RSA-2048 server key pair generate karta hai.
     *
     * <p><b>Andar kya hota hai RSA key generation mein?</b>
     * <ol>
     *   <li>SecureRandom entropy source initialize hoti hai
     *       (OS se: /dev/urandom Linux, CryptGenRandom Windows)</li>
     *   <li>Pehla prime <b>p</b> generate hota hai (~1024 bits)</li>
     *   <li>Doosra prime <b>q</b> generate hota hai (~1024 bits)</li>
     *   <li>n = p × q (yeh 2048-bit RSA modulus hai)</li>
     *   <li>λ(n) = lcm(p-1, q-1) compute hota hai</li>
     *   <li>e = 65537 (public exponent, standard Fermat prime F4)</li>
     *   <li>d = e⁻¹ mod λ(n) (private exponent)</li>
     *   <li>CRT components compute hote hain: dp, dq, qInv (speed optimization)</li>
     * </ol>
     * </p>
     *
     * <p><b>WHY RSA-2048 for server (not 4096)?</b><br>
     * TLS Server certificates typically valid 1 year. RSA-2048 is secure
     * until ~2030 per NIST. 4096 is slower for TLS handshake — thousands
     * of clients connect simultaneously. Sub CA (RSA-2048) signs with its key,
     * Root CA (RSA-4096) signed Sub CA — hierarchy provides layered security.</p>
     *
     * @return generated RSA-2048 {@link KeyPair}
     * @throws Exception if key generation fails
     */
    public static KeyPair generateServerKeyPair() throws Exception {

        log("KEYGEN", "KeyPairGenerator instance le rahe hain — Algorithm: RSA, Provider: BC");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");

        log("KEYGEN", "Key size initialize kar rahe hain: " + KEY_SIZE + " bits");
        log("KEYGEN", "SecureRandom source: OS entropy (CryptGenRandom/urandom)");
        keyGen.initialize(KEY_SIZE, new SecureRandom());

        log("KEYGEN", "Prime generation shuru... (p aur q dono ~1024-bit primes)");
        long startMs = System.currentTimeMillis();

        KeyPair keyPair = keyGen.generateKeyPair();

        long elapsed = System.currentTimeMillis() - startMs;
        log("KEYGEN", "Key pair generate hua in " + elapsed + " ms");
        log("KEYGEN", "Public key class : " + keyPair.getPublic().getClass().getSimpleName());
        log("KEYGEN", "Private key class: " + keyPair.getPrivate().getClass().getSimpleName());

        return keyPair;
    }

    // =========================================================================
    // Step 1D — Public Key Inspect
    // =========================================================================

    /**
     * Public key ki saari properties inspect aur log karta hai.
     *
     * <p><b>Public Key Structure (X.509 SubjectPublicKeyInfo):</b>
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   algorithm   AlgorithmIdentifier,   -- "RSA"
     *   subjectPublicKey  BIT STRING {      -- actual key bytes
     *     RSAPublicKey ::= SEQUENCE {
     *       modulus           INTEGER,       -- n (2048-bit number)
     *       publicExponent    INTEGER        -- e = 65537
     *     }
     *   }
     * }
     * </pre>
     * </p>
     *
     * @param keyPair generated key pair
     */
    private static void inspectPublicKey(KeyPair keyPair) {
        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

        log("PUBKEY", "Algorithm           : " + pub.getAlgorithm());
        log("PUBKEY", "Encoding Format     : " + pub.getFormat() + " (SubjectPublicKeyInfo ASN.1)");
        log("PUBKEY", "Encoded Size        : " + pub.getEncoded().length + " bytes (DER)");
        log("PUBKEY", "Modulus Bit Length  : " + pub.getModulus().bitLength() + " bits → RSA-2048 confirmed");
        log("PUBKEY", "Public Exponent (e) : " + pub.getPublicExponent() + " (65537 = Fermat prime F4, standard)");
        log("PUBKEY", "Modulus (n) first 40 hex chars: "
            + pub.getModulus().toString(16).substring(0, 40) + "...");
        log("PUBKEY", "WHY e=65537? Binary: 10000000000000001 — sirf 2 set bits → fast modular exponentiation");
    }

    // =========================================================================
    // Step 1E — Private Key Inspect
    // =========================================================================

    /**
     * Private key ki internal CRT (Chinese Remainder Theorem) structure inspect karta hai.
     *
     * <p><b>WHY CRT in private key?</b><br>
     * Standard RSA decryption uses: m = c^d mod n — bahut slow for 2048-bit numbers.
     * CRT optimization uses p, q separately:
     * <pre>
     *   m1 = c^dp mod p   (smaller: 1024-bit)
     *   m2 = c^dq mod q   (smaller: 1024-bit)
     *   m  = CRT(m1, m2)  (combine using qInv)
     * </pre>
     * Result: ~4x faster than naive RSA. Every real RSA implementation uses CRT.</p>
     *
     * @param keyPair generated key pair
     */
    private static void inspectPrivateKey(KeyPair keyPair) {
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

        log("PRIVKEY", "Algorithm           : " + priv.getAlgorithm());
        log("PRIVKEY", "Encoding Format     : " + priv.getFormat() + " (PKCS#8 PrivateKeyInfo ASN.1)");
        log("PRIVKEY", "Encoded Size        : " + priv.getEncoded().length + " bytes (DER)");
        log("PRIVKEY", "Modulus (n) bits    : " + priv.getModulus().bitLength() + " bits");
        log("PRIVKEY", "Private Exponent (d): [HIDDEN — never log in production!]");
        log("PRIVKEY", "CRT Prime p bits    : " + priv.getPrimeP().bitLength() + " bits");
        log("PRIVKEY", "CRT Prime q bits    : " + priv.getPrimeQ().bitLength() + " bits");
        log("PRIVKEY", "CRT dp (d mod p-1)  : " + priv.getPrimeExponentP().bitLength() + " bits");
        log("PRIVKEY", "CRT dq (d mod q-1)  : " + priv.getPrimeExponentQ().bitLength() + " bits");
        log("PRIVKEY", "CRT qInv (q⁻¹ mod p): " + priv.getCrtCoefficient().bitLength() + " bits");
        log("PRIVKEY", "WHY CRT? → TLS handshake 4x faster with CRT vs naive RSA decryption");
        log("PRIVKEY", "WARNING : Private key SIRF server ke paas rehni chahiye — NEVER share!");
    }

    // =========================================================================
    // Step 1F — Save Private Key to PEM
    // =========================================================================

    /**
     * Private key ko PKCS#8 PEM format mein file mein save karta hai.
     *
     * <p><b>PEM Format kya hai?</b>
     * <pre>
     * -----BEGIN PRIVATE KEY-----
     * [Base64 encoded DER bytes of PKCS#8 PrivateKeyInfo structure]
     * -----END PRIVATE KEY-----
     * </pre>
     * </p>
     *
     * <p><b>PKCS#8 vs PKCS#1 format:</b>
     * <ul>
     *   <li>PKCS#8 (BEGIN PRIVATE KEY) — algorithm-agnostic wrapper.
     *       Modern standard. Works with RSA, EC, Ed25519 all same way.</li>
     *   <li>PKCS#1 (BEGIN RSA PRIVATE KEY) — RSA-specific, legacy format.
     *       OpenSSL purana format. Avoid for new code.</li>
     * </ul>
     * </p>
     *
     * <p><b>Production mein kya karein?</b><br>
     * Yahan unencrypted PEM save kar rahe hain (learning purpose).
     * Production mein: {@code -----BEGIN ENCRYPTED PRIVATE KEY-----}
     * AES-256 passphrase se encrypt karke save karo.</p>
     *
     * @param keyPair key pair jiska private key save karna hai
     * @return PEM string (for display/logging)
     * @throws IOException if file write fails
     */
    private static String savePrivateKey(KeyPair keyPair) throws IOException {

        byte[] encoded = keyPair.getPrivate().getEncoded();
        log("SAVE", "Private key DER encoded size: " + encoded.length + " bytes");

        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                           .encodeToString(encoded);

        String pem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";

        try (FileWriter fw = new FileWriter(PRIVATE_KEY_FILE)) {
            fw.write(pem);
        }

        log("SAVE", "Private key saved → " + Paths.get(PRIVATE_KEY_FILE).toAbsolutePath());
        log("SAVE", "File size         : " + Files.size(Paths.get(PRIVATE_KEY_FILE)) + " bytes");
        log("SAVE", "PEM header        : -----BEGIN PRIVATE KEY----- (PKCS#8 format)");
        log("SAVE", "WARNING           : Yeh file NEVER git commit karein!");

        return pem;
    }

    // =========================================================================
    // Step 1G — Save Public Key to PEM
    // =========================================================================

    /**
     * Public key ko X.509 SubjectPublicKeyInfo PEM format mein save karta hai.
     *
     * <p>Public key freely shareable hai — koi risk nahi.</p>
     *
     * @param keyPair key pair jiska public key save karna hai
     * @return PEM string
     * @throws IOException if file write fails
     */
    private static String savePublicKey(KeyPair keyPair) throws IOException {

        byte[] encoded = keyPair.getPublic().getEncoded();
        log("SAVE", "Public key DER encoded size: " + encoded.length + " bytes");

        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                           .encodeToString(encoded);

        String pem = "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";

        try (FileWriter fw = new FileWriter(PUBLIC_KEY_FILE)) {
            fw.write(pem);
        }

        log("SAVE", "Public key saved  → " + Paths.get(PUBLIC_KEY_FILE).toAbsolutePath());
        log("SAVE", "File size         : " + Files.size(Paths.get(PUBLIC_KEY_FILE)) + " bytes");
        log("SAVE", "PEM header        : -----BEGIN PUBLIC KEY----- (X.509 SubjectPublicKeyInfo)");

        return pem;
    }

    // =========================================================================
    // Step 1H — Verify Files Written
    // =========================================================================

    /**
     * Save ki gayi files exist karti hain aur non-empty hain yeh verify karta hai.
     *
     * @throws IOException if verification fails
     */
    private static void verifyFilesWritten() throws IOException {
        String[] files = { PRIVATE_KEY_FILE, PUBLIC_KEY_FILE };

        for (String filePath : files) {
            Path p = Paths.get(filePath);
            boolean exists = Files.exists(p);
            long size = exists ? Files.size(p) : 0;
            log("VERIFY", filePath + " → exists=" + exists + ", size=" + size + " bytes "
                + (exists && size > 0 ? "✓" : "✗ ERROR!"));
        }
    }

    // =========================================================================
    // Summary
    // =========================================================================

    private static void printSummary(KeyPair keyPair, String privateKeyPem, String publicKeyPem) {
        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           STEP 01 SUMMARY — Server Key Pair                 ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║  Algorithm   : RSA%-43s║%n", "");
        System.out.printf( "║  Key Size    : %d bits%-43s║%n", pub.getModulus().bitLength(), "");
        System.out.printf( "║  Exponent    : %-47s║%n", pub.getPublicExponent().toString());
        System.out.printf( "║  Pub Format  : %-47s║%n", "X.509 SubjectPublicKeyInfo (PEM)");
        System.out.printf( "║  Priv Format : %-47s║%n", "PKCS#8 PrivateKeyInfo (PEM)");
        System.out.printf( "║  Saved       : %-47s║%n", PRIVATE_KEY_FILE);
        System.out.printf( "║  Saved       : %-47s║%n", PUBLIC_KEY_FILE);
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║  Next Step   : Step02_CsrGeneration.java                    ║");
        System.out.println("║  → CSR banayenge with maximum granular attributes            ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    // =========================================================================
    // Banner
    // =========================================================================

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║        TLS Server Certificate Pipeline                      ║");
        System.out.println("║        Step 01 — Server Key Pair Generation                 ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║  Package  : com.pqc.ca.tls                                  ║");
        System.out.println("║  Output   : cert/server.key.pem, cert/server.pub.pem         ║");
        System.out.println("║  Provider : BouncyCastle (bcprov + bcpkix)                  ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }

    // =========================================================================
    // Logger
    // =========================================================================

    /**
     * Structured line-by-line logger.
     *
     * <p>Format: {@code [STEP01][TAG] message}</p>
     *
     * @param tag     short category tag (KEYGEN, SAVE, VERIFY, etc.)
     * @param message log message
     */
    static void log(String tag, String message) {
        System.out.printf("[STEP01][%-8s] %s%n", tag, message);
    }
}
