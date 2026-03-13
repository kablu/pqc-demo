# Registration Authority (RA) System — Technology Stack Reference Tables
**Version:** 2.0 | **Date:** 2026-03-14 | **Project:** PKI Registration Authority
**Base:** Java 21 LTS + Spring Boot 3.3.x + Spring Framework 6.1.x

---

## 1. CORE TECHNOLOGY STACK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| JDK Runtime | Eclipse Temurin (OpenJDK) | **21.0.3 LTS** | Primary Java runtime; Virtual Threads (Project Loom), ZGC garbage collector, long-term support until 2029 |
| JDK Alt | Amazon Corretto | **21.0.3 LTS** | AWS-optimized OpenJDK distribution; drop-in Temurin alternative |
| Application Framework | Spring Boot | **3.3.4** | Auto-configuration, embedded Tomcat, production-ready starter POMs |
| Core Framework | Spring Framework | **6.1.12** | Dependency injection, AOP, AOT compilation, virtual thread executor support |
| Web Layer | Spring Web MVC | **6.1.12** | REST controllers, EST/SCEP/CMP/ACME protocol endpoint handling |
| Build Tool | Apache Maven | **3.9.9** | Multi-module build, dependency management, CI/CD integration |
| Build Tool Alt | Gradle | **8.10** | DSL-based alternative build system |
| API Gateway | Spring Cloud Gateway | **4.1.5** | Request routing, rate limiting, mTLS termination, circuit breaker |
| Workflow Engine | Spring State Machine | **3.2.1** | Certificate request lifecycle FSM (Submitted → Validated → Approved → Issued) |
| Async Processing | Spring Async + Virtual Threads | **JDK 21 built-in** | High-throughput non-blocking certificate request processing |
| REST Documentation | SpringDoc OpenAPI (Swagger UI) | **2.6.0** | Auto-generated API docs from annotations |
| Input Validation | Hibernate Validator (Jakarta) | **8.0.1.Final** | Bean validation for CSR fields, DN patterns, profile constraints |
| JSON Serialization | Jackson Databind | **2.17.2** | REST payload serialization/deserialization |
| gRPC (Internal) | grpc-spring-boot-starter | **3.1.0** | High-performance internal service-to-service communication |
| Operator Frontend | React + TypeScript | **18.3 / 5.5** | RA Operator web portal — request approval, search, revocation UI |
| Frontend Build | Vite | **5.4** | Fast React build tooling |

---

## 2. SECURITY STACK *(Critical for PKI Systems)*

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Security Framework | Spring Security | **6.3.3** | AuthN/AuthZ, method-level RBAC (`@PreAuthorize`), filter chain |
| OAuth2 / OIDC | Spring Security OAuth2 Resource Server | **6.3.3** | JWT validation, Keycloak token integration |
| Identity Provider | Keycloak | **25.0.6** | OIDC / OAuth2 / SAML2 identity broker; operator SSO, TOTP MFA |
| LDAP / AD Integration | Spring LDAP | **3.2.4** | Active Directory user lookup, RA subscriber identity verification |
| Secrets Management | HashiCorp Vault | **1.17.6** | HSM PIN storage, DB credentials, API keys — zero plaintext secrets |
| Vault Spring Integration | Spring Vault | **3.1.2** | Dynamic secrets, lease renewal, PKI secrets engine |
| Smart Card / FIDO2 | WebAuthn4J | **0.28.3** | PIV smart card + YubiKey (FIDO2) authentication for RA Officers |
| mTLS Enforcement | Spring Security + Netty TLS | **TLS 1.3** | Mutual TLS for CA-facing, admin, and subscriber endpoints |
| TLS Configuration | `jdk.tls.disabledAlgorithms` JVM flag | JDK 21 | Disable SSLv3, TLS 1.0, TLS 1.1, RC4, DES, MD5withRSA |
| Service Mesh mTLS | Istio (STRICT mode) | **1.23.2** | Automatic mTLS between all Kubernetes pods |
| WAF | ModSecurity + OWASP Core Rule Set | **3.3.7 / 4.7** | OWASP Top-10 protection at ingress layer |
| Ingress TLS | Nginx Ingress Controller | **1.11.2** | TLS termination, certificate-based client auth at edge |
| Container Security | Distroless Java 21 base image | **latest** | No shell, no package manager — minimal attack surface |
| Pod Security | Kubernetes Pod Security Standards | **Restricted** | `runAsNonRoot`, `readOnlyRootFilesystem`, drop ALL capabilities |
| Image Signing | Cosign + Notation | **2.4.1 / 1.2.0** | Supply chain integrity — sign and verify container images |
| CVE Scanning | Trivy | **0.56.2** | Container + dependency CVE scanning in CI/CD; block on CRITICAL |
| RBAC (Application) | Spring Security + Keycloak Roles | **6.3.x** | RA_OPERATOR, RA_OFFICER, RA_MANAGER, RA_AUDITOR, RA_ADMIN |
| Rate Limiting | Spring Cloud Gateway + Redis | **4.1.5** | Per-IP, per-subscriber, per-profile request throttling |
| HTTP Security Headers | Spring Security (built-in) | **6.3.3** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| JWT Lifecycle | Keycloak tokens | Access: 15 min / Refresh: 8 hr | Short-lived tokens to limit blast radius on compromise |

---

## 3. CRYPTOGRAPHIC LIBRARY STACK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Primary Crypto Library | Bouncy Castle FIPS Java API | **2.0.0** | FIPS 140-2 Level 1 validated (Cert #4616); RSA, ECDSA, AES-GCM, SHA-2/3 |
| PKIX / Certificate Ops | Bouncy Castle PKIX FIPS | **2.0.4** | X.509 cert parsing, PKCS#10 CSR handling, CRL/OCSP building, CMP/CMC |
| Protocol / Utility | Bouncy Castle (non-FIPS) | **1.78.1** | EST, SCEP, CMP protocol message parsing where FIPS mode not enforced |
| PKCS#11 Bridge | SunPKCS11 (JDK built-in) | **JDK 21** | JCE provider bridge to HSM via PKCS#11 interface |
| Post-Quantum (KEM) | ML-KEM-768 (JEP 496) | **Java 24 / BC 1.78** | NIST FIPS 203 — Module-Lattice Key Encapsulation; quantum-safe key exchange |
| Post-Quantum (Sign) | ML-DSA-65 (JEP 497) | **Java 24 / BC 1.78** | NIST FIPS 204 — Module-Lattice Digital Signatures; quantum-safe signing |
| TLS Post-Quantum | X25519MLKEM768 hybrid | **JDK 24 / TLS 1.3** | Hybrid classical+PQ key exchange for TLS connections |
| JVM FIPS Mode | `java.security.properties` override | JDK 21 | Restrict JVM to FIPS-approved algorithms only |

---

## 4. DATABASE LAYER

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Primary RDBMS | PostgreSQL | **16.4** | Core RA data: certificate requests, workflow state, entities, profiles |
| JDBC Driver | PostgreSQL JDBC | **42.7.4** | Type-safe JDBC connectivity; SSL/TLS client cert auth to DB |
| Connection Pool | HikariCP | **5.1.0** | Ultra-low latency connection pooling; built into Spring Boot |
| ORM | Hibernate ORM | **6.5.3.Final** | JPA entity mapping; optimistic locking for concurrent request updates |
| Data Access | Spring Data JPA | **3.3.4** | Repository abstraction, derived queries, pagination for cert search |
| Schema Migration | Flyway | **10.18.0** | Versioned SQL migrations; repeatable scripts for reference data |
| Partitioning | PostgreSQL native partitioning | **16.4** | Partition `certificates` table by `issued_at` month for query performance |
| Backup & Recovery | pgBackRest | **2.53** | Continuous WAL archiving, point-in-time recovery (PITR), S3/local storage |
| HA Replication | Patroni + etcd | **3.3.2 / 3.5.x** | PostgreSQL HA cluster with automatic failover; RPO < 15 min |
| DB Secrets | HashiCorp Vault (DB secrets engine) | **1.17.6** | Dynamic short-lived DB credentials; no static passwords |

---

## 5. MESSAGING & ASYNCHRONOUS PROCESSING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Message Broker | Apache Kafka | **3.8.0** | Async certificate event streaming: issuance events, revocation events, audit pipeline |
| Kafka Client | Spring Kafka | **3.2.4** | `@KafkaListener` for consuming CA callback events; producer for audit events |
| Kafka Schema | Apache Avro + Schema Registry | **1.11.3 / 7.7.x** | Typed event schemas for `CertificateIssuedEvent`, `RevocationRequestedEvent` |
| Task Scheduling | Spring Scheduler (`@Scheduled`) | **6.1.x built-in** | CRL generation jobs, certificate expiry notification, OCSP cache refresh |
| Async Executor | Spring Async + Virtual Thread Executor | **JDK 21** | Non-blocking HSM signing operations; concurrent CSR batch processing |
| Dead Letter Queue | Kafka DLQ topic | **3.8.0** | Failed CA forwarding retries; alerting on repeated failures |
| Event Outbox | Transactional Outbox Pattern (PostgreSQL) | Custom impl | Guaranteed-delivery of domain events to Kafka without distributed transactions |

---

## 6. CACHING LAYER

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| In-Memory Cache | Redis | **7.4.0** | Central cache store for all RA caching needs |
| Redis Client | Lettuce (via Spring Data Redis) | **6.3.2** | Reactive, thread-safe Redis client; connection pooling |
| Spring Cache Abstraction | Spring Cache (`@Cacheable`) | **6.1.x built-in** | Declarative caching on service methods |
| OCSP Response Cache | Redis with TTL | **7.4.0** | Cache OCSP responses (TTL = nextUpdate - now); reduces OCSP responder load |
| CRL Cache | Redis with TTL | **7.4.0** | Cache latest CRL bytes; refreshed by scheduled job on each CRL publication |
| Certificate Profile Cache | Spring Cache + Redis | **7.4.0** | Cache certificate profile configs (validity, key usage, SAN policy) |
| Session / Token Cache | Redis | **7.4.0** | Operator portal session state, JWT refresh token blacklist |
| Rate Limit Counters | Redis (INCR + EXPIRE) | **7.4.0** | Sliding-window rate limit counters per IP/subscriber/profile |
| CA Connector Cache | Caffeine (local L1) | **3.1.8** | Local in-process cache for CA certificate chain; reduces latency |
| Redis HA | Redis Sentinel / Redis Cluster | **7.4.0** | 3-node sentinel for HA; cluster mode for horizontal scale at high volume |

---

## 7. OBSERVABILITY & MONITORING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Metrics Library | Micrometer | **1.13.6** | JVM metrics, custom RA business metrics (cert issuance rate, queue depth) |
| Metrics Backend | Prometheus | **2.54.1** | Time-series metrics scraping and storage |
| Dashboards | Grafana | **11.2.0** | RA KPI dashboards: issuance rates, revocation counts, HSM ops, approval queue |
| Alerting | Grafana Alertmanager | **0.27.0** | PagerDuty/Slack alerts for HSM failure, cert spike anomaly, expiry warnings |
| Distributed Tracing | OpenTelemetry Java Agent | **1.40.0** | Auto-instrumentation of Spring Boot; trace per certificate request end-to-end |
| Trace Backend | Grafana Tempo | **2.6.0** | Store and query distributed traces; integrates with Grafana UI |
| Log Aggregation | Elasticsearch | **8.15.2** | Centralized log storage and full-text search |
| Log Processing | Logstash | **8.15.2** | Parse, enrich, and route structured logs from all RA services |
| Log Shipper | Filebeat | **8.15.2** | Lightweight log forwarder from Kubernetes pods to Logstash |
| Log Visualization | Kibana | **8.15.2** | Log search UI, security dashboards, operational views |
| Structured Logging | Logback + Logstash Logback Encoder | **1.5.8 / 7.4** | JSON-formatted log output with MDC: requestId, operatorId, serialNumber |
| Health Endpoints | Spring Boot Actuator | **3.3.4** | `/actuator/health/liveness`, `/actuator/health/readiness` for K8s probes |
| SIEM Integration | Splunk Universal Forwarder | **9.3.0** | Forward structured audit events to enterprise SIEM in real-time |
| Uptime Monitoring | Grafana Synthetic Monitoring | **1.x** | Probe EST, OCSP, CRL endpoints every 60 seconds; SLA tracking |

**Key Custom Prometheus Metrics:**

| Metric | Labels | Alert Threshold |
|--------|--------|-----------------|
| `ra_certificate_requests_total` | `{protocol, status, profile}` | — |
| `ra_certificate_issuance_duration_seconds` | `{profile}` | p99 > 5s |
| `ra_hsm_operations_total` | `{operation, status}` | any `status=error` |
| `ra_ocsp_requests_total` | `{status}` | error rate > 1% |
| `ra_csr_validation_failures_total` | `{reason}` | spike > baseline×3 |
| `ra_approval_queue_size` | — | > 100 pending |
| `ra_certificate_expiry_days` | `{serial, subject}` | < 30 days |
| `ra_revocations_total` | `{reason}` | `keyCompromise` > 0 |

---

## 8. AUDIT & COMPLIANCE

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Immutable Audit Store | immudb | **1.9.5** | Cryptographically tamper-evident audit log; hash-chained, append-only |
| immudb Java Client | immudb4j | **1.0.1** | `verifiedSet` / `verifiedGet` — throws exception if data was tampered |
| Audit Event DB | PostgreSQL (`audit_events` table) | **16.4** | Relational audit log with hash-chain column; queryable for compliance reports |
| Audit Log Signing | Hash-chained SHA-256 | Custom impl | Each audit record stores `SHA256(prev_hash + event_data)`; chain verifiable |
| SIEM Pipeline | Splunk + Universal Forwarder | **9.3.0** | Real-time audit event forwarding to enterprise SIEM for SOC monitoring |
| Compliance Reporting | Spring Batch + JasperReports | **5.1.2 / 6.21.3** | Scheduled compliance reports: issuance counts, revocations, operator actions |
| CT Log Integration | Google Trillian (RFC 6962) | **1.7.0** | Certificate Transparency log submission for publicly-trusted TLS certificates |
| Key Ceremony Audit | M-of-N quorum logging | Custom impl | Multi-person key ceremony events recorded with HSM attestation |
| Regulatory Standards | RFC 5280, FIPS 140-2, NIST SP 800-57 | — | X.509 profile compliance, key management lifecycle |
| eIDAS Compliance | EU Regulation 910/2014 profiles | — | QCP-n, QCP-l certificate profiles for EU qualified certificates |

---

## 9. HSM INTEGRATION

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| HSM Hardware | Utimaco SecurityServer Se Series | **v5.x** | FIPS 140-2 Level 3 validated HSM; RA signing key storage |
| HSM Alt (On-Prem) | Thales Luna Network HSM 7 | **7.x** | Alternative FIPS 140-3 Level 3 HSM |
| HSM Alt (Cloud) | AWS CloudHSM | **Latest** | Cloud-native FIPS 140-2 Level 3; for hybrid AWS deployments |
| HSM Alt (Cloud) | Azure Dedicated HSM | **Latest** | Azure FIPS 140-2 Level 3 dedicated HSM |
| PKCS#11 Bridge | SunPKCS11 (JDK built-in provider) | **JDK 21** | JCE-to-PKCS#11 bridge; enables `KeyStore.getInstance("PKCS11")` |
| PKCS#11 Middleware | Utimaco CryptoServer JCE/PKCS#11 | **v5.x** | Native PKCS#11 library `.so` / `.dll` loaded by SunPKCS11 |
| Key Usage | RA Signing Key (RSA-4096 / ECDSA P-384) | HSM-resident | Signs OCSP responses, CMP messages; never extracted from HSM |
| Key Usage | TLS Server Key | HSM-resident | RA server private key for mTLS endpoints |
| PIN Management | HashiCorp Vault | **1.17.6** | HSM operator PIN stored as Vault secret; injected at runtime via env |
| TPM Integration | tpm2-tools + TSS4J | **1.0.1** | Device attestation for IoT certificate enrollment workflows |
| HSM HA | Utimaco cluster mode | **v5.x** | Active-active HSM cluster; automatic failover for signing operations |

---

## 10. CA INTEGRATION

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| CA Backend | EJBCA Community / Enterprise | **8.3.x** | Enterprise-grade CA; RA forwards approved CSRs via CMP |
| CA Protocol | CMP (RFC 4210) over mTLS | BC 1.78.1 | Standard CA management protocol; `ir` (Initial Request), `cr` (Cert Request) |
| CA Protocol Alt | CMC (RFC 5272) | BC 1.78.1 | Certificate Management over CMS; advanced RA-to-CA channel |
| EJBCA Java Client | EJBCA WS / REST client | **8.3.x** | SOAP/REST API for certificate issuance, revocation, profile management |
| CA Certificate Cache | Caffeine (local L1) | **3.1.8** | Cache CA certificate chain in memory; refresh every 24h or on change |
| CA Failover | Spring Retry + CircuitBreaker (Resilience4j) | **2.2.0** | Retry failed CA calls; open circuit after 5 failures; fallback to queue |
| Multiple CA Support | CA Connector abstraction interface | Custom impl | Pluggable `CaConnector` interface; supports EJBCA, MS ADCS, AWS Private CA |
| Certificate Profiles | EJBCA profile management | **8.3.x** | TLS/SSL, S/MIME, Code Signing, Client Auth, IoT Device profiles |
| MS ADCS Integration | Microsoft ADCS via CEP/CES | Windows Server 2022 | Optional: enterprise Windows environments using MS PKI |
| AWS Private CA | AWS ACM Private CA Java SDK | **2.28.x** | Optional: hybrid cloud RA forwarding to AWS-managed CA |

---

## 11. INFRASTRUCTURE & DEPLOYMENT

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Containerization | Docker | **27.3.1** | Multi-stage builds; distroless runtime images |
| Container Runtime | containerd | **1.7.x** | K8s container runtime |
| Orchestration | Kubernetes | **1.31.x** | Production RA cluster; Pod Security Standards: Restricted |
| Helm | Helm | **3.16.x** | RA system Helm chart packaging and versioned deployments |
| Service Mesh | Istio | **1.23.2** | mTLS STRICT between all pods; traffic policies; observability |
| Ingress | Nginx Ingress Controller | **1.11.2** | TLS/mTLS termination; WAF integration |
| Secrets Injection | External Secrets Operator (ESO) | **0.10.x** | Sync HashiCorp Vault secrets into K8s Secrets |
| HA Load Balancer | MetalLB | **0.14.8** | On-prem L4 load balancer; VIP for RA API endpoints |
| Image Registry | Harbor | **2.11.1** | Private OCI registry; built-in Trivy scanning + image signing |
| Config Management | Ansible | **2.17.5** | Node hardening automation; K8s node baseline config |
| GitOps | ArgoCD | **2.12.x** | Declarative K8s deployment from Git; audit trail of all infra changes |
| CI/CD | GitHub Actions / Jenkins | Latest | Build → Test → Scan → Sign → Deploy pipeline |

---

## 12. TESTING STACK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Unit Testing | JUnit 5 (Jupiter) | **5.11.2** | Unit tests for crypto operations, CSR validation, workflow logic |
| Mocking | Mockito | **5.14.1** | Mock HSM, CA connector, LDAP in unit tests |
| Integration Testing | Spring Boot Test | **3.3.4** | Full Spring context tests with `@SpringBootTest` |
| Container Testing | Testcontainers | **1.20.2** | Spin up real PostgreSQL, Redis, Keycloak, Kafka in tests |
| API Contract | WireMock | **3.9.1** | Mock EJBCA CMP/REST endpoints; offline CA simulation |
| PKI Test Data | Bouncy Castle test utilities | **1.78.1** | Generate test CA, sign test CSRs, build test cert chains |
| Performance | k6 | **0.54.x** | Load test: 100K cert requests/day simulation; EST/SCEP endpoints |
| Security Testing | OWASP ZAP | **2.15.x** | Automated API security scanning in CI pipeline |
| Mutation Testing | PIT (Pitest) | **1.17.x** | Validate test suite quality for crypto/validation logic |

---

## 13. CERTIFICATE ENROLLMENT PROTOCOL STACK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| EST Server | Custom Spring MVC + BC PKIX | **RFC 7030** | `/.well-known/est` — modern TLS client enrollment; simpleenroll, simplereenroll, cacerts |
| SCEP Server | JSCEP | **2.5.1** | Simple Certificate Enrollment Protocol; legacy network devices, IoT, MDM |
| CMP Client/Server | Bouncy Castle CMP | **BC 1.78.1** | RFC 4210 — RA-to-CA protocol; ir/ip/cr/cp/rr/rp message handling |
| ACME Server | Custom Spring + BC | **RFC 8555** | Automated cert lifecycle for TLS; compatible with Let's Encrypt clients |
| CMC | Bouncy Castle CMC | **BC 1.78.1** | RFC 5272 — advanced full PKI request/response for enterprise RA |
| OCSP Responder | Custom Spring Boot + BC | **RFC 6960** | Real-time certificate status; Redis-cached responses; HSM-signed |
| CRL Service | BC X509v2CRLBuilder + Nginx | **RFC 5280** | CRL generation (scheduled) + static file hosting via Nginx CDN |
| CT Log Client | Google Trillian client | **1.7.0** | RFC 6962 — submit issued TLS certs to Certificate Transparency logs |

---

## COMPLETE DEPENDENCY VERSION MANIFEST (pom.xml)

```xml
<properties>
    <!-- ===== RUNTIME ===== -->
    <java.version>21</java.version>
    <spring-boot.version>3.3.4</spring-boot.version>
    <spring-framework.version>6.1.12</spring-framework.version>
    <spring-security.version>6.3.3</spring-security.version>
    <spring-statemachine.version>3.2.1</spring-statemachine.version>
    <spring-cloud.version>2023.0.3</spring-cloud.version>
    <spring-vault.version>3.1.2</spring-vault.version>
    <spring-ldap.version>3.2.4</spring-ldap.version>
    <spring-kafka.version>3.2.4</spring-kafka.version>
    <spring-batch.version>5.1.2</spring-batch.version>

    <!-- ===== CRYPTOGRAPHY ===== -->
    <bc-fips.version>2.0.0</bc-fips.version>
    <bcpkix-fips.version>2.0.4</bcpkix-fips.version>
    <bcprov.version>1.78.1</bcprov.version>

    <!-- ===== DATABASE ===== -->
    <postgresql.version>42.7.4</postgresql.version>
    <hikaricp.version>5.1.0</hikaricp.version>
    <flyway.version>10.18.0</flyway.version>
    <hibernate.version>6.5.3.Final</hibernate.version>
    <immudb4j.version>1.0.1</immudb4j.version>

    <!-- ===== MESSAGING ===== -->
    <kafka.version>3.8.0</kafka.version>
    <avro.version>1.11.3</avro.version>

    <!-- ===== CACHING ===== -->
    <lettuce.version>6.3.2.RELEASE</lettuce.version>
    <caffeine.version>3.1.8</caffeine.version>

    <!-- ===== PROTOCOLS ===== -->
    <jscep.version>2.5.1</jscep.version>

    <!-- ===== RESILIENCE ===== -->
    <resilience4j.version>2.2.0</resilience4j.version>

    <!-- ===== OBSERVABILITY ===== -->
    <micrometer.version>1.13.6</micrometer.version>
    <opentelemetry.version>1.40.0</opentelemetry.version>
    <logstash-encoder.version>7.4</logstash-encoder.version>

    <!-- ===== TESTING ===== -->
    <junit.version>5.11.2</junit.version>
    <testcontainers.version>1.20.2</testcontainers.version>
    <mockito.version>5.14.1</mockito.version>
    <wiremock.version>3.9.1</wiremock.version>
</properties>
```

---

*PKI Architecture Team | Confidential — Internal Use Only | Next Review: 2026-09-14*
