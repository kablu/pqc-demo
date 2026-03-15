package com.pqc;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * =========================================================================
 * CertificateStore — Shared In-Memory State for Task01 through Task08
 * =========================================================================
 *
 * <p>
 * This class acts as a simple in-memory store so that the CA key pair and
 * CA certificate generated in Task02 can be reused by Tasks 03–08 without
 * duplicating key generation code. In production, keys live in an HSM and
 * certs are stored in a database or PKCS#12 keystore.
 * </p>
 *
 * <p><b>WHY static fields?</b><br>
 * Each task's {@code main()} runs in the same JVM. Static fields allow tasks
 * to share state without complex dependency injection. This is a LEARNING-ONLY
 * pattern — real systems use proper key management (Vault, HSM, PKCS#11).</p>
 *
 * @author PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class CertificateStore {

    /**
     * The CA's RSA key pair — generated once, used by all tasks.
     *
     * <p>In production: CA private key is ALWAYS HSM-resident.
     * It is NEVER in memory as a Java object outside controlled HSM sessions.</p>
     */
    public static KeyPair caKeyPair;

    /**
     * The self-signed CA certificate — the root of trust for all issued certs.
     *
     * <p>In production: CA cert is stored in a Trust Store (JKS/PKCS12)
     * and distributed to all clients that need to trust it.</p>
     */
    public static X509Certificate caCert;

    /**
     * The end-entity (subscriber) key pair — generated in Task03.
     *
     * <p>In production: subscriber's key pair is generated ON THEIR system.
     * The private key NEVER leaves the subscriber. Only the CSR (with public key)
     * is sent to the RA for certificate issuance.</p>
     */
    public static KeyPair entityKeyPair;

    /**
     * The issued end-entity certificate — result of Task04.
     *
     * <p>Reused in Tasks 05 (CRL), 06 (OCSP), 07 (CMS), 08 (PKCS#12).</p>
     */
    public static java.security.cert.X509Certificate entityCert;

    // Private constructor — prevent instantiation. This is a utility class.
    private CertificateStore() {}
}
