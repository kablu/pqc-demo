package com.pqc.ca;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * =========================================================================
 * CaStore — In-Memory PKI Hierarchy State for com.pqc.ca package
 * =========================================================================
 *
 * <p>
 * Root CA aur Sub CA ke key pairs aur certificates ko in-memory store karta
 * hai taaki {@link RootCa}, {@link SubCa}, aur {@link CaHierarchyDemo} mein
 * share ho sake bina duplicate code ke.
 * </p>
 *
 * <h2>Production Mein Kya Hota Hai?</h2>
 * <ul>
 *   <li><b>Root CA Private Key</b> — HSM (Hardware Security Module) mein
 *       offline vault mein locked rehti hai. Internet se NEVER connected.</li>
 *   <li><b>Sub CA Private Key</b> — Online HSM mein rehti hai lekin air-gapped
 *       network segment pe. Sirf signing operations ke liye accessible.</li>
 *   <li><b>Certificates</b> — Database ya LDAP directory mein store hoti hain.
 *       Public hoti hain — freely distribute kar sakte hain.</li>
 * </ul>
 *
 * <h2>PKI Hierarchy Kya Hai?</h2>
 * <pre>
 * Root CA (Self-Signed)
 *   └── Sub CA (Signed by Root CA)
 *         ├── TLS Server Certificate (Signed by Sub CA)
 *         ├── TLS Client Certificate (Signed by Sub CA)
 *         └── S/MIME Certificate     (Signed by Sub CA)
 * </pre>
 *
 * <p><b>WHY two-tier hierarchy?</b><br>
 * Root CA private key online nahi hoti — agar compromise ho jaaye toh
 * poora PKI destroyed ho jaata hai. Sub CA online rehti hai aur certificates
 * issue karti hai. Agar Sub CA compromise ho, sirf Sub CA revoke karo —
 * Root CA safe rehti hai aur naya Sub CA issue karo.</p>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-07-04
 * @see     RootCa
 * @see     SubCa
 * @see     CaHierarchyDemo
 */
public class CaStore {

    // =========================================================================
    // Root CA State
    // =========================================================================

    /**
     * Root CA RSA-4096 key pair.
     *
     * <p>WHY RSA-4096 for Root CA? Root CA certificate 20 years tak valid
     * rehti hai. NIST recommends RSA-4096 for keys protecting data beyond 2030.
     * Root CA key generation offline ceremony mein hoti hai — airgapped machine pe.</p>
     */
    public static KeyPair rootCaKeyPair;

    /**
     * Root CA self-signed X.509v3 certificate — the ultimate trust anchor.
     *
     * <p>Yeh certificate kisi aur ne sign nahi kiya. Isko "trust anchor" ya
     * "trust root" kehte hain. Browser/OS ke built-in Trust Store mein
     * pre-installed hota hai (e.g., DigiCert, GlobalSign, Let's Encrypt roots).</p>
     */
    public static X509Certificate rootCaCert;

    // =========================================================================
    // Sub CA State
    // =========================================================================

    /**
     * Sub CA RSA-2048 key pair.
     *
     * <p>WHY RSA-2048 for Sub CA (not 4096)? Sub CA certificates typically
     * valid for 10 years. RSA-2048 is secure through 2030+ per NIST. Also,
     * Sub CA signs thousands of end-entity certs — faster signing with 2048.
     * In practice, EC P-384 is even better (smaller keys, faster operations).</p>
     */
    public static KeyPair subCaKeyPair;

    /**
     * Sub CA X.509v3 certificate — signed by Root CA.
     *
     * <p>Chain verification path: End-entity cert → Sub CA cert → Root CA cert.
     * TLS client downloads sub CA cert via AIA extension, verifies chain up to
     * trusted root in its trust store.</p>
     */
    public static X509Certificate subCaCert;

    // Private constructor — utility class, no instantiation.
    private CaStore() {}
}
