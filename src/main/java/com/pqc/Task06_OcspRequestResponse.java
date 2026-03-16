package com.pqc;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.operator.DigestCalculatorProvider;

/**
 * =========================================================================
 * Task 06 — OCSP Request and Response (Online Certificate Status Protocol)
 * =========================================================================
 *
 * <h2>Purpose / Kya Seekhenge?</h2>
 * <p>
 * OCSP (RFC 6960) ek real-time certificate status check protocol hai.
 * Client (browser) ek specific certificate ka status check karta hai — GOOD,
 * REVOKED, ya UNKNOWN. CRL ke comparison mein yeh much faster aur bandwidth
 * efficient hai kyunki puri list download nahi hoti.
 * </p>
 *
 * <h2>OCSP Flow (RA System Mein)</h2>
 * <pre>
 * [TLS Client]                [RA/OCSP Responder]              [CA]
 *     │                              │                           │
 *     │── OCSP Request ─────────────►│                           │
 *     │   (certId = issuer+serial)   │── verify against DB ─────►│
 *     │                              │◄─ cert status ────────────│
 *     │◄─ OCSP Response ─────────────│                           │
 *     │   (GOOD / REVOKED / UNKNOWN) │                           │
 *     │                              │                           │
 * </pre>
 *
 * <h2>OCSP vs CRL (Comparison)</h2>
 * <pre>
 * OCSP                              CRL (Task05)
 * ────────────────────────────      ─────────────────────────────
 * Per-cert real-time query          Download full list
 * Small request/response            Large file (grows with revocations)
 * Requires responder online         Works offline (cached)
 * OCSP Stapling = no privacy issue  Direct download exposes cert usage
 * Used by all modern browsers       Legacy, enterprise PKI
 * Spring Boot RA has OCSP endpoint  Published to HTTP CDN
 * </pre>
 *
 * <h2>Run Command</h2>
 * <pre>./gradlew run -PmainClass=com.pqc.Task06_OcspRequestResponse</pre>
 *
 * @author  PKI-RA Learning Series
 * @version 1.0
 * @since   2026-03-15
 */
public class Task06_OcspRequestResponse {

    /** Shared SecureRandom instance — reused for nonce generation. */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Builds a BC digest calculator provider using the BouncyCastle provider. */
    private static DigestCalculatorProvider buildDigestProvider() throws Exception {
        return new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
    }

    /**
     * Entry point — builds an OCSP request and then builds the signed response.
     *
     * @param args command-line arguments (not used)
     * @throws Exception if OCSP processing fails
     */
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Task 06 — OCSP Request and Response");
        System.out.println("=============================================================\n");

        Task01_RsaKeyPairGeneration.registerBouncyCastleProvider();

        if (CertificateStore.entityCert == null) {
            Task04_IssueCertFromCsr.main(new String[]{});
        }

        // Part A — OCSP REQUEST (what the TLS client sends)
        System.out.println("── Part A: OCSP Request (Client Side) ──────────────────────\n");
        OCSPReq ocspRequest = buildOcspRequest(CertificateStore.entityCert.getSerialNumber());
        printOcspRequest(ocspRequest);

        // Part B — OCSP RESPONSE for GOOD status (cert valid)
        System.out.println("── Part B: OCSP Response — GOOD Status ──────────────────────\n");
        OCSPResp goodResponse = buildOcspResponse(ocspRequest, CertificateStatus.GOOD);
        parseAndPrintOcspResponse(goodResponse, "GOOD");

        // Part C — OCSP RESPONSE for REVOKED status (cert revoked)
        System.out.println("── Part C: OCSP Response — REVOKED Status ───────────────────\n");
        OCSPResp revokedResponse = buildOcspResponse(ocspRequest,
            new RevokedStatus(
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),  // revoked yesterday
                org.bouncycastle.asn1.x509.CRLReason.keyCompromise   // key was compromised
            ));
        parseAndPrintOcspResponse(revokedResponse, "REVOKED");

        System.out.println("✅ Task 06 Complete — OCSP request/response demonstrated!");
        System.out.println("   Next Step → Task07_CmsSignedData.java");
    }

    // =========================================================================
    // Part A — Build OCSP Request (Client Side)
    // =========================================================================

    /**
     * Builds an OCSP request for a specific certificate serial number.
     *
     * <p><b>WHY OCSPReqBuilder?</b><br>
     * {@link OCSPReqBuilder} constructs the ASN.1 OCSPRequest structure (RFC 6960).
     * It bundles the CertID (which uniquely identifies the cert to check) and
     * an optional nonce (for replay protection).</p>
     *
     * <p><b>CertID — How Does OCSP Identify a Certificate?</b><br>
     * CertID = SHA-1( issuerName || issuerKey || serialNumber ).
     * WHY SHA-1? RFC 6960 mandates SHA-1 for CertID by default. SHA-1 is
     * deprecated for signatures but still used here for OCSP interoperability.
     * RFC 8954 extends OCSP with SHA-256 CertIDs.</p>
     *
     * <p><b>Nonce — WHY?</b><br>
     * Nonce (Number Once) is a random value that the client sends and expects
     * the responder to echo back. Prevents replay attacks — an attacker cannot
     * reuse an old "GOOD" response because the nonce won't match.
     * RFC 8954 made nonces mandatory for new implementations.</p>
     *
     * @param certSerial the serial number of the certificate to check
     * @return the built {@link OCSPReq}
     * @throws Exception if CertID creation fails
     */
    public static OCSPReq buildOcspRequest(BigInteger certSerial) throws Exception {
        System.out.println("📤 Building OCSP Request for serial: 0x" + certSerial.toString(16));

        // DigestCalculatorProvider: provides SHA-1 digest for CertID computation
        // WHY SHA-1 here? CertID standard hash algorithm per RFC 6960
        DigestCalculatorProvider digestProvider = buildDigestProvider();

        // CertificateID uniquely identifies the certificate at this issuer
        // Parameters: (digestCalculator, issuerCert, certSerial)
        // digestCalculator computes SHA-1 of issuer name + issuer key
        CertificateID certId = new CertificateID(
            digestProvider.get(CertificateID.HASH_SHA1),  // SHA-1 digest algorithm
            new JcaX509CertificateHolder(CertificateStore.caCert),  // issuer's certificate
            certSerial  // serial number of the cert being queried
        );

        // Create OCSP request builder
        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();

        // addRequest(certId) — add one certificate to check
        // A single OCSP request can contain MULTIPLE CertIDs (batch check)
        reqBuilder.addRequest(certId);

        // ---- Nonce Extension ----
        // Generate a random 16-byte nonce for replay protection
        byte[] nonceBytes = new byte[16];
        SECURE_RANDOM.nextBytes(nonceBytes); // cryptographically random bytes

        // Add nonce as an OCSP extension
        // OCSPObjectIdentifiers.id_pkix_ocsp_nonce = OID for OCSP nonce extension
        reqBuilder.setRequestExtensions(
            new Extensions(new Extension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false,  // NOT critical — responders may not support nonce
                new org.bouncycastle.asn1.DEROctetString(nonceBytes)
            ))
        );

        // build() — produces the unsigned OCSP request
        // WHY unsigned? Basic OCSP requests are typically unsigned.
        // Signed OCSP requests are used when responder requires client auth.
        OCSPReq request = reqBuilder.build();
        System.out.println("✔ OCSP Request built\n");
        return request;
    }

    /**
     * Prints the details of an OCSP request.
     *
     * @param request the OCSP request to inspect
     * @throws Exception if request parsing fails
     */
    public static void printOcspRequest(OCSPReq request) throws Exception {
        System.out.println("📋 OCSP Request Details:");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");
        System.out.printf( "   │ Encoded Size   : %d bytes%n", request.getEncoded().length);
        System.out.printf( "   │ Is Signed      : %s%n", request.isSigned());
        System.out.printf( "   │ Cert IDs Count : %d%n", request.getRequestList().length);

        // Print each CertID being queried
        for (org.bouncycastle.cert.ocsp.Req req : request.getRequestList()) {
            CertificateID cid = req.getCertID();
            System.out.println("   │ ── CertID ──────────────────────────────────────── │");
            System.out.println("   │   Hash Algorithm : " + cid.getHashAlgOID());
        }
        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // Part B — Build OCSP Response (Responder/RA Side)
    // =========================================================================

    /**
     * Builds a signed OCSP response with the specified certificate status.
     *
     * <p><b>WHY BasicOCSPRespBuilder?</b><br>
     * OCSP response has two layers:
     * <ol>
     *   <li>{@code BasicOCSPResp} — the actual status data + signature</li>
     *   <li>{@code OCSPResp} — outer wrapper with response status code</li>
     * </ol>
     * {@link BasicOCSPRespBuilder} builds the signed inner layer. Then
     * {@link OCSPRespBuilder} wraps it in the outer envelope.</p>
     *
     * <p><b>thisUpdate / nextUpdate:</b><br>
     * thisUpdate = when this response was signed (now).
     * nextUpdate = when this response expires (clients should refresh).
     * RA caches OCSP responses in Redis with TTL = nextUpdate - now (Task06 in RA stack).</p>
     *
     * <p><b>OCSP Response Status Codes (outer wrapper):</b>
     * <ul>
     *   <li>{@code SUCCESSFUL(0)}  — response built correctly (check inner status)</li>
     *   <li>{@code MALFORMED_REQUEST(1)} — request was malformed</li>
     *   <li>{@code INTERNAL_ERROR(2)}    — responder internal failure</li>
     *   <li>{@code TRY_LATER(3)}         — responder temporarily overloaded</li>
     *   <li>{@code SIG_REQUIRED(5)}      — request must be signed</li>
     *   <li>{@code UNAUTHORIZED(6)}      — responder refuses this request</li>
     * </ul>
     * </p>
     *
     * @param request    the OCSP request to respond to
     * @param certStatus {@link CertificateStatus#GOOD}, {@link RevokedStatus}, or UnknownStatus
     * @return the signed {@link OCSPResp}
     * @throws Exception if response building or signing fails
     */
    public static OCSPResp buildOcspResponse(OCSPReq request,
                                              CertificateStatus certStatus) throws Exception {
        System.out.println("📥 Building OCSP Response — status: "
            + (certStatus == CertificateStatus.GOOD ? "GOOD" : "REVOKED/UNKNOWN"));

        // ---- Responder ID ----
        // Identifies who is signing this response (the OCSP Responder / RA)
        // byKey = identify responder by its public key hash (common approach)
        // byName = identify responder by its DN (alternative)
        X509CertificateHolder responderCertHolder =
            new JcaX509CertificateHolder(CertificateStore.caCert);

        // Create BasicOCSPRespBuilder
        // In production: OCSP responder has its OWN key pair (delegated from CA)
        // Here we reuse the CA key for simplicity
        BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(
            new org.bouncycastle.cert.ocsp.RespID(responderCertHolder.getSubject())
        );

        // ---- Timing ----
        Instant now       = Instant.now();
        Date    thisUpdate = Date.from(now);
        Date    nextUpdate = Date.from(now.plus(1, ChronoUnit.HOURS)); // cache for 1 hour

        // ---- Add Single Response for the requested cert ----
        DigestCalculatorProvider digestProvider = buildDigestProvider();

        // Recreate the CertID that matches the request
        CertificateID certId = new CertificateID(
            digestProvider.get(CertificateID.HASH_SHA1),
            responderCertHolder,
            CertificateStore.entityCert.getSerialNumber()
        );

        // addResponse(certId, status, thisUpdate, nextUpdate)
        // certStatus = GOOD (null in BC API) means certificate is valid
        // certStatus = RevokedStatus means certificate was revoked
        // certStatus = UnknownStatus means responder has no info
        respBuilder.addResponse(certId, certStatus, thisUpdate, nextUpdate, null);

        // ---- Sign the BasicOCSPResp ----
        org.bouncycastle.operator.ContentSigner respSigner =
            new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(CertificateStore.caKeyPair.getPrivate());

        // build(signer, chain, producedAt)
        // chain = array of certs the client can use to verify this response's signer
        BasicOCSPResp basicResp = respBuilder.build(
            respSigner,
            new X509CertificateHolder[]{ responderCertHolder },
            Date.from(now)
        );

        // ---- Wrap in outer OCSPResp ----
        // OCSPRespBuilder.SUCCESSFUL = response status 0 = request processed successfully
        // The actual cert status (GOOD/REVOKED) is inside basicResp
        OCSPRespBuilder outerBuilder = new OCSPRespBuilder();
        OCSPResp finalResponse = outerBuilder.build(
            OCSPRespBuilder.SUCCESSFUL,  // outer status = request OK
            basicResp                    // inner status = cert GOOD/REVOKED
        );

        System.out.println("✔ OCSP Response built and signed\n");
        return finalResponse;
    }

    /**
     * Parses and prints the contents of an OCSP response.
     *
     * @param response    the OCSP response to parse
     * @param expectedStatus human-readable expected status label
     * @throws Exception if response parsing fails
     */
    public static void parseAndPrintOcspResponse(OCSPResp response,
                                                   String expectedStatus) throws Exception {
        System.out.println("📋 OCSP Response (" + expectedStatus + "):");
        System.out.println("   ┌──────────────────────────────────────────────────────┐");

        // getStatus() = outer response status (0=SUCCESSFUL)
        System.out.println("   │ Response Status : " + response.getStatus()
            + (response.getStatus() == 0 ? " (SUCCESSFUL)" : " (ERROR)"));

        System.out.printf( "   │ Encoded Size    : %d bytes%n", response.getEncoded().length);

        // Parse the inner BasicOCSPResp
        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();

        // getProducedAt() = when the responder generated this response
        System.out.println("   │ Produced At     : " + basicResp.getProducedAt());

        // getCerts() = certificates included by responder for signature verification
        System.out.println("   │ Responder Certs : " + basicResp.getCerts().length);

        // getResponses() = array of single-cert status responses
        for (SingleResp singleResp : basicResp.getResponses()) {
            System.out.println("   │ ── Single Response ─────────────────────────────── │");
            System.out.println("   │   This Update   : " + singleResp.getThisUpdate());
            System.out.println("   │   Next Update   : " + singleResp.getNextUpdate());

            // getCertStatus() = null means GOOD; RevokedStatus / UnknownStatus otherwise
            CertificateStatus status = singleResp.getCertStatus();
            if (status == CertificateStatus.GOOD) {
                System.out.println("   │   Cert Status   : ✅ GOOD — certificate is valid");
            } else if (status instanceof RevokedStatus rs) {
                System.out.println("   │   Cert Status   : 🚫 REVOKED");
                System.out.println("   │   Revoked At    : " + rs.getRevocationTime());
                if (rs.hasRevocationReason()) {
                    System.out.println("   │   Reason Code   : " + rs.getRevocationReason());
                }
            } else {
                System.out.println("   │   Cert Status   : ❓ UNKNOWN");
            }
        }
        System.out.println("   └──────────────────────────────────────────────────────┘\n");
    }
}
