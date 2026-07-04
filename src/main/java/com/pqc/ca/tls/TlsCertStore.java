package com.pqc.ca.tls;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * =========================================================================
 * TlsCertStore — Shared In-Memory State for TLS Server Certificate Pipeline
 * =========================================================================
 *
 * <p>
 * Step01 se Step05 tak ka shared state yahan store hota hai.
 * Har Step apna output yahan save karta hai aur agla Step yahan se
 * input leta hai — bina duplicate code ke.
 * </p>
 *
 * <pre>
 * Step01_ServerKeyPairGeneration  → serverKeyPair
 *         ↓
 * Step02_CsrGeneration            → serverCsr, csrPem
 *         ↓
 * Step03_CsrSubmissionToSubCa     → reads serverCsr, validates
 *         ↓
 * Step04_CertificateIssuance      → serverCert, serverCertPem
 *         ↓
 * Step05_Pkcs12AndChainVerification → reads all above
 * </pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-07-04
 */
public class TlsCertStore {

    /** Server RSA-2048 key pair — generated in Step01 */
    public static KeyPair serverKeyPair;

    /** PKCS#10 CSR object — built in Step02 */
    public static PKCS10CertificationRequest serverCsr;

    /** CSR in PEM string format — saved to cert/server.csr.pem in Step02 */
    public static String csrPem;

    /** Issued TLS Server X.509 certificate — signed by Sub CA in Step04 */
    public static X509Certificate serverCert;

    /** Certificate in PEM string format — saved to cert/server.crt.pem in Step04 */
    public static String serverCertPem;

    private TlsCertStore() {}
}
