# Registration Authority (RA) System — Technology Stack Reference Tables
**Version:** 2.1 | **Date:** 2026-03-14 | **Project:** PKI Registration Authority
**Base:** Java 21 LTS + Spring Boot 4.0.3 + Spring Framework 7.0.6

> ⚠️ **Migration Note:** Spring Boot 4.0 requires Java 17 minimum (Java 21 recommended). Upgrade path: `3.3.x → 3.5.x → 4.0.x`. Spring Framework 7.0 is the aligned core framework.

---

## 1. CORE TECHNOLOGY STACK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| JDK Runtime | Eclipse Temurin (OpenJDK) | **21.0.3 LTS** | Primary Java runtime; Virtual Threads (Project Loom), ZGC garbage collector, long-term support until 2029 |
| JDK Alt | Amazon Corretto | **21.0.3 LTS** | AWS-optimized OpenJDK distribution; drop-in Temurin alternative |
| Application Framework | Spring Boot | **4.0.3** *(Feb 2026)* | Auto-configuration, embedded Tomcat 11, production-ready starter POMs; JSpecify null-safety, API Versioning, Java 25 support |
| Core Framework | Spring Framework | **7.0.6** *(Mar 2026)* | Dependency injection, AOP, AOT compilation, virtual thread executor; Jakarta EE 11, JSpecify null annotations |
| Web Layer | Spring Web MVC | **7.0.6** *(Mar 2026)* | REST controllers, EST/SCEP/CMP/ACME protocol endpoint handling; multiple-view-per-request support |
| Build Tool | Apache Maven | **3.9.9** | Multi-module build, dependency management, CI/CD integration |
| Build Tool Alt | Gradle | **9.4.0** *(Mar 2026)* | DSL-based build system; Java 26 support, stable task graph, improved test reporting, Spring Boot 4.0 compatible |
| API Gateway | Spring Cloud Gateway | **4.2.x** *(2025.0.x BOM)* | Request routing, rate limiting, mTLS termination, circuit breaker; Spring Boot 4.0 aligned |
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
| Security Framework | Spring Security | **7.0.x** *(Spring Boot 4.0 aligned)* | AuthN/AuthZ, method-level RBAC (`@PreAuthorize`), filter chain; Jakarta EE 11 compatible |
| OAuth2 / OIDC | Spring Security OAuth2 Resource Server | **7.0.x** | JWT validation, Keycloak token integration; Spring Boot 4.0 aligned |
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
| RBAC (Application) | Spring Security + Keycloak Roles | **7.0.x** | RA_OPERATOR, RA_OFFICER, RA_MANAGER, RA_AUDITOR, RA_ADMIN |
| Rate Limiting | Spring Cloud Gateway + Redis | **4.2.x** | Per-IP, per-subscriber, per-profile request throttling |
| HTTP Security Headers | Spring Security (built-in) | **7.0.x** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
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
| Integration Testing | Spring Boot Test | **4.0.3** | Full Spring context tests with `@SpringBootTest` |
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

## 14. SPRING BOOT TEST TECH STACK

> Spring Boot 4.0 Test module (`spring-boot-starter-test`) is the **all-in-one** test dependency.
> It auto-includes JUnit 5, Mockito, AssertJ, Hamcrest, JSONAssert, JsonPath, and Awaitility.

---

### 14A. CORE TEST FRAMEWORK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Test Starter | `spring-boot-starter-test` | **4.0.3** | Master test BOM — includes JUnit 6, Mockito, AssertJ, Hamcrest, JSONAssert, JsonPath, Awaitility |
| Test Runner | JUnit 6 (Jupiter Engine) | **6.0.3** *(Feb 2026)* | `@Test`, `@ParameterizedTest`, `@Nested`, `@ExtendWith` — requires Java 17+; current generation |
| Test Runner (LTS) | JUnit 5 (Jupiter Engine) | **5.13.4** | Latest JUnit 5.x line; use if SB 4.0 BOM hasn't adopted JUnit 6 yet |
| JUnit Platform | JUnit Platform Launcher | **1.13.4** | Test discovery and execution engine; Maven Surefire + Gradle 9 Test integration |
| Mocking Framework | Mockito Core | **5.23.0** *(Mar 2026)* | `@Mock`, `@InjectMocks`, `@Captor` — mock HSM service, CA connector, LDAP provider |
| Spring Mock Beans | `@MockBean` / `@SpyBean` | **4.0.3** | Replace Spring beans with Mockito mocks inside `ApplicationContext` |
| Assertion Library | AssertJ | **3.27.7** *(Jan 2026)* | Fluent assertions: `assertThat(cert).isNotNull().hasFieldOrProperty("serialNumber")`; CVE-2026-24400 patched |
| Assertion Alt | Hamcrest | **2.2** | Matcher-based assertions; used with MockMvc `andExpect(jsonPath(...))` |
| JSON Assertion | JSONAssert | **1.5.3** | Assert JSON REST response bodies: `strict` vs `lenient` mode |
| JSON Path | JsonPath (Jayway) | **2.9.0** | `$.certificates[0].subject` — navigate JSON responses in test assertions |
| Async Assertion | Awaitility | **4.2.2** | `await().atMost(5, SECONDS).until(...)` — test async cert issuance, Kafka consumers |

---

### 14B. SPRING BOOT TEST SLICES *(Context-Scoped Tests)*

> Test slices load only the relevant layer of the Spring context — faster than full `@SpringBootTest`

| Slice Annotation | Technology | Version | Purpose / What It Loads |
|---|---|---|---|
| `@SpringBootTest` | Spring Boot Test | **4.0.3** | Full application context; end-to-end integration test for complete RA workflow |
| `@WebMvcTest` | Spring Boot Test | **4.0.3** | Only Spring MVC layer (controllers, filters, `@ControllerAdvice`); use for `EstController`, `ScepController`, `OcspController` |
| `@DataJpaTest` | Spring Boot Test | **4.0.3** | Only JPA layer (Hibernate, DataSource, Flyway); H2 in-memory by default; use for `CertificateRequestRepository` tests |
| `@DataRedisTest` | Spring Boot Test | **4.0.3** | Only Redis auto-configuration; use with `@EmbeddedRedis` or Testcontainers Redis |
| `@RestClientTest` | Spring Boot Test | **4.0.3** | Only `RestClient` / `RestTemplate` auto-config; use to test EJBCA REST connector |
| `@JsonTest` | Spring Boot Test | **4.0.3** | Only Jackson serialization; test `CertificateRequestDto`, `OcspResponseDto` JSON mapping |
| `@WebFluxTest` | Spring Boot Test | **4.0.3** | Only WebFlux layer; for reactive OCSP / EST endpoints |
| `@SpringBatchTest` | Spring Batch Test | **5.2.x** | Spring Batch job testing; use for CRL generation job, cert expiry notification batch |
| `@MockMvcTest` (custom) | Spring Security Test | **7.0.x** | Test `SecurityFilterChain`, mTLS, `@PreAuthorize` on RA endpoints |

---

### 14C. WEB LAYER TESTING (MockMvc / WebTestClient)

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| MockMvc | Spring Test (`MockMvc`) | **7.0.6** | Test Spring MVC controllers without real HTTP; simulates EST/SCEP/OCSP HTTP calls |
| MockMvc Auto-config | `@AutoConfigureMockMvc` | **4.0.3** | Auto-wire `MockMvc` in `@SpringBootTest` without manual setup |
| MockMvc Security | `SecurityMockMvcConfigurer` | **7.0.x** | Test `@PreAuthorize`, `@Secured`, mTLS client cert injection via `with(x509(cert))` |
| WebTestClient | Spring WebFlux Test | **7.0.6** | Reactive HTTP test client; fluent API for reactive OCSP/EST endpoint testing |
| TestRestTemplate | Spring Boot Test | **4.0.3** | Full HTTP integration test with real embedded server (`@SpringBootTest(webEnvironment=RANDOM_PORT)`) |
| MockMvc PKI Helper | Spring Security X.509 | **7.0.x** | `mockMvc.perform(get("/est/cacerts").with(x509(clientCert)))` — inject client cert in tests |

**Sample MockMvc Test (EST Endpoint):**
```java
@WebMvcTest(EstController.class)
@AutoConfigureMockMvc
class EstControllerTest {

    @Autowired MockMvc mockMvc;
    @MockBean  CertificateRequestService requestService;

    @Test
    void simpleEnroll_validCsr_returns200() throws Exception {
        byte[] csrDer = TestPkiHelper.generateCsr("CN=test-device");

        mockMvc.perform(post("/.well-known/est/simpleenroll")
                .contentType("application/pkcs10")
                .content(csrDer)
                .with(x509(TestPkiHelper.clientCert())))   // mTLS simulation
            .andExpect(status().isOk())
            .andExpect(content().contentType("application/pkcs7-mime"));
    }
}
```

---

### 14D. TESTCONTAINERS (Real Infrastructure in Tests)

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Testcontainers Core | Testcontainers | **1.20.2** | Docker-based real infra in tests; no mocks for DB/cache/messaging |
| PostgreSQL Module | `testcontainers-postgresql` | **1.20.2** | Real PostgreSQL 16 container for `@DataJpaTest` / `@SpringBootTest` |
| Redis Module | `testcontainers-redis` | **1.20.2** | Real Redis 7.4 container for OCSP cache, session, rate-limit tests |
| Kafka Module | `testcontainers-kafka` | **1.20.2** | Real Kafka 3.8 container for `CertificateIssuedEvent` consumer tests |
| Keycloak Module | `testcontainers-keycloak` | **3.4.0** | Real Keycloak 25 container for OAuth2/JWT integration tests |
| Vault Module | `testcontainers-vault` | **1.20.2** | Real HashiCorp Vault for dynamic secrets testing |
| immudb Module | Custom Docker container | **1.9.5** | Real immudb for audit log integration tests |
| Spring Boot Integration | `@ServiceConnection` | **4.0.3** | Auto-wire Testcontainers into Spring `@Bean`s — zero manual config |

**Sample Testcontainers Setup:**
```java
@SpringBootTest
@Testcontainers
class CertificateRequestServiceIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
        new PostgreSQLContainer<>("postgres:16");

    @Container
    @ServiceConnection
    static RedisContainer redis =
        new RedisContainer(DockerImageName.parse("redis:7.4"));

    @Autowired CertificateRequestService service;

    @Test
    void submitRequest_persistsToDbAndCachesStatus() {
        var request = service.submit(TestPkiHelper.validCsrRequest());
        assertThat(request.getStatus()).isEqualTo(PENDING_VALIDATION);
    }
}
```

---

### 14E. SECURITY & PKI-SPECIFIC TESTING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Spring Security Test | `spring-security-test` | **7.0.x** | `@WithMockUser`, `@WithUserDetails`, `SecurityMockMvcRequestPostProcessors` |
| X.509 Mock | `SecurityMockMvcRequestPostProcessors.x509()` | **7.0.x** | Inject mock client certificate for mTLS endpoint tests |
| OAuth2 Mock | `SecurityMockMvcRequestPostProcessors.jwt()` | **7.0.x** | Inject mock JWT with RA roles for `@PreAuthorize` tests |
| PKI Test Data Generator | Bouncy Castle (test scope) | **1.78.1** | Generate self-signed CA, issue test certificates, build PKCS#10 CSRs in tests |
| PKCS#11 HSM Simulator | SoftHSM2 (via Testcontainers) | **2.6.1** | Software HSM for CI/CD — no real Utimaco needed in test pipeline |
| OCSP Mock | WireMock | **3.9.1** | Mock EJBCA OCSP responses; test RA revocation logic offline |
| CMP Mock | WireMock | **3.9.1** | Mock EJBCA CMP `ip` (InitializationResponse) for CA connector tests |

---

### 14F. API CONTRACT & EXTERNAL MOCK TESTING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| WireMock | WireMock | **3.9.1** | Standalone HTTP mock server; simulate EJBCA REST/CMP, LDAP HTTP, CT log |
| Spring Cloud Contract | Spring Cloud Contract | **4.1.x** | Consumer-driven contract tests between RA and CA integration layer |
| Pact | Pact JVM | **4.6.x** | Alternative CDC (Consumer-Driven Contract) testing for RA ↔ CA REST API |
| REST-assured | REST-assured | **5.5.0** | Fluent DSL for full HTTP integration tests against running RA server |
| Spring Cloud WireMock | `spring-cloud-contract-wiremock` | **4.1.x** | Auto-configure WireMock stubs from Spring Cloud Contract specs |

---

### 14G. PERFORMANCE & LOAD TESTING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Load Testing | k6 | **0.54.x** | Simulate 100K cert requests/day; EST/SCEP/ACME endpoint throughput |
| JVM Profiler | Async-profiler + JFR | **3.0 / JDK 21** | CPU/memory profiling during load tests; identify HSM signing bottlenecks |
| Benchmarking | JMH (Java Microbenchmark Harness) | **1.37** | Micro-benchmark crypto operations: CSR parsing, cert signing, OCSP response time |
| Gatling | Gatling | **3.11.x** | Alternative load testing; Scala/Java DSL; rich HTML reports |

---

### 14H. CODE QUALITY & MUTATION TESTING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Mutation Testing | PIT (Pitest) | **1.17.1** | Inject code mutations; validate test suite kills all mutants in crypto/validation code |
| Code Coverage | JaCoCo | **0.8.12** | Line/branch coverage reports; enforce 80%+ coverage gate in CI/CD |
| Static Analysis | SonarQube / SonarCloud | **10.6.x** | Code quality, security hotspots, CVE detection in RA source code |
| Checkstyle | Checkstyle + Maven plugin | **10.18.x** | Enforce PKI team coding standards; no raw crypto, proper exception handling |
| SpotBugs | SpotBugs + Find Security Bugs | **4.8.6** | Static bug + security vulnerability detection (`HARD_CODE_KEY`, `WEAK_CIPHER`) |
| OWASP Dependency Check | OWASP Dependency-Check Maven | **10.0.4** | Scan `pom.xml` dependencies for known CVEs; fail build on CVSS ≥ 7 |

---

### 14I. COMPLETE TEST DEPENDENCY MANIFEST (pom.xml test scope)

```xml
<!-- ===== SPRING BOOT TEST STACK ===== -->
<dependencies>

    <!-- Master test starter — includes JUnit 5, Mockito, AssertJ, Hamcrest, JSONAssert, JsonPath, Awaitility -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <version>4.0.3</version>
        <scope>test</scope>
    </dependency>

    <!-- Spring Security Test — @WithMockUser, x509(), jwt() post-processors -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <version>7.0.x</version>
        <scope>test</scope>
    </dependency>

    <!-- Testcontainers — real PostgreSQL, Redis, Kafka, Keycloak, Vault -->
    <dependency>
        <groupId>org.testcontainers</groupId>
        <artifactId>testcontainers-bom</artifactId>
        <version>1.20.2</version>
        <type>pom</type>
        <scope>import</scope>
    </dependency>
    <dependency>
        <groupId>org.testcontainers</groupId>
        <artifactId>junit-jupiter</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.testcontainers</groupId>
        <artifactId>postgresql</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.testcontainers</groupId>
        <artifactId>kafka</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>com.redis</groupId>
        <artifactId>testcontainers-redis</artifactId>
        <version>2.2.2</version>
        <scope>test</scope>
    </dependency>

    <!-- WireMock — mock EJBCA CMP/REST, OCSP, CT log endpoints -->
    <dependency>
        <groupId>org.wiremock</groupId>
        <artifactId>wiremock</artifactId>
        <version>3.9.1</version>
        <scope>test</scope>
    </dependency>

    <!-- REST-assured — fluent HTTP test DSL -->
    <dependency>
        <groupId>io.rest-assured</groupId>
        <artifactId>rest-assured</artifactId>
        <version>5.5.0</version>
        <scope>test</scope>
    </dependency>

    <!-- JMH — microbenchmark crypto & signing operations -->
    <dependency>
        <groupId>org.openjdk.jmh</groupId>
        <artifactId>jmh-core</artifactId>
        <version>1.37</version>
        <scope>test</scope>
    </dependency>

    <!-- Bouncy Castle — PKI test data: generate CA, CSRs, certs -->
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78.1</version>
        <scope>test</scope>
    </dependency>

</dependencies>
```

---

### 14J. TEST LAYER SUMMARY MAP

```
┌─────────────────────────────────────────────────────────────────────┐
│              RA SYSTEM — TEST PYRAMID                               │
├──────────────────────────────┬──────────────────────────────────────┤
│ TEST TYPE                    │ TOOLS USED                           │
├──────────────────────────────┼──────────────────────────────────────┤
│ Unit Tests                   │ JUnit 5 + Mockito + AssertJ          │
│ (crypto, validation, FSM)    │ @ExtendWith(MockitoExtension.class)  │
├──────────────────────────────┼──────────────────────────────────────┤
│ Slice Tests (fast)           │ @WebMvcTest  → MockMvc               │
│ (controller / JPA / Redis)   │ @DataJpaTest → H2 in-memory          │
│                              │ @JsonTest    → Jackson mapping        │
├──────────────────────────────┼──────────────────────────────────────┤
│ Integration Tests            │ @SpringBootTest + Testcontainers      │
│ (full context + real infra)  │ Real PostgreSQL / Redis / Kafka       │
│                              │ WireMock for EJBCA / OCSP             │
├──────────────────────────────┼──────────────────────────────────────┤
│ Security Tests               │ spring-security-test                  │
│ (RBAC / mTLS / JWT)          │ x509(), jwt(), @WithMockUser          │
├──────────────────────────────┼──────────────────────────────────────┤
│ API Contract Tests           │ Spring Cloud Contract / Pact          │
│ (RA ↔ CA interface)          │ Consumer-Driven Contract              │
├──────────────────────────────┼──────────────────────────────────────┤
│ Performance Tests            │ k6 (100K req/day) + JMH (micro)      │
│ (load / benchmark)           │ Gatling (alternative)                 │
├──────────────────────────────┼──────────────────────────────────────┤
│ Security Scanning            │ OWASP ZAP + SpotBugs + Dep-Check     │
│ (SAST / DAST / CVE)          │ SonarQube + Checkstyle                │
├──────────────────────────────┼──────────────────────────────────────┤
│ Mutation Testing             │ PIT (Pitest) — kill mutants           │
│ (test quality gate)          │ JaCoCo — 80%+ coverage gate           │
└──────────────────────────────┴──────────────────────────────────────┘
```

---

## 15. JUNIT, MOCKITO & TEST CASE WRITING LIBRARIES

> This section covers every library needed to **write** unit, integration, and security test cases
> for the RA system — from test runners and mocking to assertions and parameterization.

---

### 15A. TEST RUNNERS & FRAMEWORK

| Component | Technology | Version (Latest) | Maven / Gradle Artifact | Purpose |
|---|---|---|---|---|
| JUnit 6 Engine | JUnit Jupiter | **6.0.3** *(Feb 2026)* | `org.junit.jupiter:junit-jupiter:6.0.3` | Current generation test runner; Java 17+ required; `@Test`, `@Nested`, `@DisplayName` |
| JUnit 5 Engine | JUnit Jupiter (5.x LTS) | **5.13.4** | `org.junit.jupiter:junit-jupiter:5.13.4` | LTS fallback if Spring Boot BOM still on 5.x |
| JUnit Platform | JUnit Platform Launcher | **1.13.4** | `org.junit.platform:junit-platform-launcher` | Test discovery, filtering, engine execution |
| JUnit Platform Suite | JUnit Platform Suite | **1.13.4** | `org.junit.platform:junit-platform-suite` | `@Suite`, `@SelectPackages` — aggregate test suites |
| Maven Surefire | Maven Surefire Plugin | **3.5.2** | `org.apache.maven.plugins:maven-surefire-plugin` | Run JUnit 6 tests in Maven `test` phase |
| Gradle Test | Gradle Test Task | **9.4.0** | Built-in | Run tests with `./gradlew test` — JUnit Platform support |
| JUnit Vintage | JUnit Vintage Engine | **5.13.4** | `org.junit.vintage:junit-vintage-engine` | Run legacy JUnit 4 tests in JUnit 5/6 platform |

---

### 15B. MOCKITO — MOCKING FRAMEWORK

| Component | Technology | Version (Latest) | Maven Artifact | Purpose |
|---|---|---|---|---|
| Mockito Core | Mockito | **5.23.0** *(Mar 2026)* | `org.mockito:mockito-core:5.23.0` | Core mocking framework; `mock()`, `when()`, `verify()`, `spy()` |
| Mockito JUnit 5 | Mockito JUnit Jupiter Extension | **5.23.0** | `org.mockito:mockito-junit-jupiter:5.23.0` | `@ExtendWith(MockitoExtension.class)` — auto inject `@Mock`, `@InjectMocks` |
| Mockito Inline | Mockito Inline (default in 5.x) | **5.23.0** | Built into `mockito-core` 5.x | Mock `final` classes, `static` methods, constructors; default mock maker |
| Spring MockBean | `@MockBean` / `@SpyBean` | **4.0.3** *(SB 4.0)* | `spring-boot-test:4.0.3` | Replace Spring beans in `ApplicationContext` with Mockito mocks |
| Mockito Kotlin | mockito-kotlin | **6.2.3** | `org.mockito.kotlin:mockito-kotlin:6.2.3` | Kotlin-friendly Mockito DSL (if Kotlin used in RA tests) |

**Key Mockito Annotations for RA Tests:**

| Annotation | Scope | RA Usage Example |
|---|---|---|
| `@Mock` | Unit test | Mock `HsmService`, `CaConnector`, `LdapIdentityProvider` |
| `@InjectMocks` | Unit test | Inject mocks into `CertificateRequestService`, `ValidationService` |
| `@Spy` | Unit test | Partial mock of `CsrValidator` — spy on real method, stub one |
| `@Captor` | Unit test | Capture `CertificateRequest` passed to `auditService.log()` |
| `@MockBean` | Spring slice test | Replace real `EjbcaCaConnector` bean in `@WebMvcTest` context |
| `@SpyBean` | Spring slice test | Spy on real `WorkflowService` in `@SpringBootTest` |

---

### 15C. ASSERTION LIBRARIES

| Component | Technology | Version (Latest) | Maven Artifact | Purpose |
|---|---|---|---|---|
| AssertJ Core | AssertJ | **3.27.7** *(Jan 2026)* | `org.assertj:assertj-core:3.27.7` | Fluent, type-safe assertions; CVE-2026-24400 XXE fix included |
| AssertJ DB | AssertJ-DB | **3.0.0** | `org.assertj:assertj-db:3.0.0` | Assert database state — verify rows in `certificate_requests` table |
| Hamcrest | Hamcrest | **2.2** | `org.hamcrest:hamcrest:2.2` | Matcher-based assertions; used in MockMvc `andExpect(jsonPath(..., is(...)))` |
| JSONAssert | JSONAssert | **1.5.3** | `org.skyscreamer:jsonassert:1.5.3` | Compare JSON responses; `strict` mode for REST API contract validation |
| JsonPath | Jayway JsonPath | **2.9.0** | `com.jayway.jsonpath:json-path:2.9.0` | Extract values from JSON response: `$.request.status`, `$.certificates[0].serial` |
| Truth | Google Truth | **1.4.4** | `com.google.truth:truth:1.4.4` | Alternative fluent assertion library from Google |

**Common AssertJ patterns for PKI/RA:**
```java
// Certificate assertions
assertThat(issuedCert)
    .isNotNull()
    .extracting(X509Certificate::getSubjectX500Principal)
    .hasToString("CN=device-001, O=MyOrg");

// Request workflow state assertions
assertThat(request.getStatus()).isEqualTo(RequestStatus.ISSUED);
assertThat(request.getCertificateSerialNumber()).isNotBlank();

// Exception assertions (invalid CSR)
assertThatThrownBy(() -> csrValidator.validate(invalidCsr))
    .isInstanceOf(CsrValidationException.class)
    .hasMessageContaining("Key size below minimum");

// DB assertion (AssertJ-DB)
assertThat(dbTable("certificate_requests"))
    .row().value("status").isEqualTo("ISSUED")
    .value("profile_id").isEqualTo("TLS_SERVER");
```

---

### 15D. PARAMETERIZED & DATA-DRIVEN TESTING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| `@ParameterizedTest` | JUnit 6 / JUnit 5 | **6.0.3 / 5.13.4** | Run same test with multiple inputs — test CSR with different key sizes, algorithms |
| `@ValueSource` | JUnit Jupiter | Built-in | `@ValueSource(strings = {"RSA", "ECDSA", "ML-KEM"})` |
| `@CsvSource` | JUnit Jupiter | Built-in | Inline CSV test data — profile name, key algo, expected validity days |
| `@MethodSource` | JUnit Jupiter | Built-in | Stream of `Arguments` from factory method — complex CSR objects |
| `@EnumSource` | JUnit Jupiter | Built-in | Iterate over `CertificateProfile` enum values in tests |
| `@ArgumentsSource` | JUnit Jupiter | Built-in | Custom `ArgumentsProvider` for generating test X.509 certificates |
| `@CsvFileSource` | JUnit Jupiter | Built-in | Load test data from `src/test/resources/test-csr-data.csv` |

---

### 15E. TEST LIFECYCLE & ORGANIZATION ANNOTATIONS

| Annotation | Framework | Purpose |
|---|---|---|
| `@Test` | JUnit 6 / 5 | Mark method as a test case |
| `@Nested` | JUnit 6 / 5 | Organize related tests in inner classes — `class WhenCsrIsInvalid {}` |
| `@DisplayName` | JUnit 6 / 5 | Human-readable test names in reports |
| `@BeforeEach` / `@AfterEach` | JUnit 6 / 5 | Set up / tear down per test — initialize BC crypto provider |
| `@BeforeAll` / `@AfterAll` | JUnit 6 / 5 | One-time class setup — start Testcontainers, generate test CA |
| `@Tag` | JUnit 6 / 5 | `@Tag("pki")`, `@Tag("hsm")` — run tagged test subsets in CI |
| `@Disabled` | JUnit 6 / 5 | Skip flaky HSM hardware tests in CI pipeline |
| `@Timeout` | JUnit 6 / 5 | `@Timeout(5)` — fail slow OCSP tests exceeding 5 seconds |
| `@TempDir` | JUnit 6 / 5 | Inject temp directory for CRL file generation tests |
| `@ExtendWith` | JUnit 6 / 5 | `@ExtendWith(MockitoExtension.class)`, `@ExtendWith(SpringExtension.class)` |
| `@ActiveProfiles` | Spring Test | `@ActiveProfiles("test")` — activate test profile (H2, mock HSM) |
| `@TestPropertySource` | Spring Test | Override `application.properties` for specific test scenarios |
| `@DirtiesContext` | Spring Test | Force context reload after tests that modify Spring beans |
| `@WithMockUser` | Spring Security | `@WithMockUser(roles = "RA_OFFICER")` — test RBAC authorization |
| `@WithUserDetails` | Spring Security | Load real `UserDetails` from test `UserDetailsService` |

---

### 15F. TEST UTILITY LIBRARIES

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Apache Commons Lang | `commons-lang3` | **3.17.0** | `RandomStringUtils`, `StringUtils` — generate test DN strings, serial numbers |
| Faker / Datafaker | Datafaker | **2.4.2** | Generate realistic test data: organization names, email SANs, IP addresses |
| Awaitility | Awaitility | **4.2.2** | Poll async conditions: `await().until(() -> repo.findByStatus(ISSUED).isPresent())` |
| Instancio | Instancio | **5.3.0** | Auto-generate populated Java objects for test fixtures — `CertificateRequest`, `AuditEvent` |
| EasyRandom | Easy Random | **6.2.1** | Random `CertificateRequest` object generation for property-based tests |
| Spring Test DBUnit | DBUnit + Spring | **1.3.0** | Seed database with test certificate data; verify DB state post-workflow |

---

## 16. ASCIIDOCTOR DOCUMENTATION TECH STACK

> AsciiDoctor is used for generating **living documentation** — API docs, architecture guides,
> and operator manuals — directly from test snippets and source code for the RA system.

---

### 16A. CORE ASCIIDOCTOR TOOLCHAIN

| Component | Technology | Version (Latest) | Maven / Gradle Artifact | Purpose |
|---|---|---|---|---|
| Asciidoctor Maven Plugin | asciidoctor-maven-plugin | **3.2.0** | `org.asciidoctor:asciidoctor-maven-plugin:3.2.0` | Convert `.adoc` files → HTML5 / PDF / DocBook; main doc build tool |
| Asciidoctor Gradle Plugin | asciidoctor-gradle-jvm | **4.0.3** | `org.asciidoctor.jvm.convert` | Gradle equivalent; `asciidoctorj { version = '3.0.0' }` |
| AsciidoctorJ | AsciidoctorJ | **3.0.0** | `org.asciidoctor:asciidoctorj:3.0.0` | Java API wrapping Asciidoctor (JRuby-based); required by Maven/Gradle plugin |
| AsciidoctorJ PDF | asciidoctorj-pdf | **2.3.19** | `org.asciidoctor:asciidoctorj-pdf:2.3.19` | Generate PDF output from `.adoc` — RA architecture docs, runbooks |
| AsciidoctorJ EPUB3 | asciidoctorj-epub3 | **2.1.3** | `org.asciidoctor:asciidoctorj-epub3:2.1.3` | Generate EPUB3 e-book format from AsciiDoc |
| Asciidoctor Diagram | asciidoctorj-diagram | **2.3.1** | `org.asciidoctor:asciidoctorj-diagram:2.3.1` | Render PlantUML, Mermaid, C4 diagrams inline in AsciiDoc |

---

### 16B. SPRING REST DOCS + ASCIIDOCTOR *(API Documentation from Tests)*

| Component | Technology | Version (Latest) | Maven Artifact | Purpose |
|---|---|---|---|---|
| Spring REST Docs Core | spring-restdocs-core | **4.0.0** | `org.springframework.restdocs:spring-restdocs-core:4.0.0` | Generate documentation snippets from MockMvc / WebTestClient tests |
| Spring REST Docs AsciiDoctor | spring-restdocs-asciidoctor | **4.0.0** | `org.springframework.restdocs:spring-restdocs-asciidoctor:4.0.0` | AsciidoctorJ 3.0 extension; include auto-generated snippets in `.adoc` files |
| Spring REST Docs MockMvc | spring-restdocs-mockmvc | **4.0.0** | `org.springframework.restdocs:spring-restdocs-mockmvc:4.0.0` | Document EST `/simpleenroll`, OCSP, CRL endpoints via MockMvc tests |
| Spring REST Docs WebTestClient | spring-restdocs-webtestclient | **4.0.0** | `org.springframework.restdocs:spring-restdocs-webtestclient:4.0.0` | Document reactive RA endpoints via `WebTestClient` |
| Spring Auto REST Docs | spring-auto-restdocs | **2.0.11** | `capital.scalable:spring-auto-restdocs-core:2.0.11` | Auto-document request/response fields from Jackson + JavaDoc |

**Spring REST Docs flow:**
```
MockMvc Test → REST Docs Snippets (.adoc) → Asciidoctor Maven Plugin → HTML5 / PDF API Docs
```

---

### 16C. OPENAPI / SWAGGER DOCUMENTATION

| Component | Technology | Version (Latest) | Maven Artifact | Purpose |
|---|---|---|---|---|
| SpringDoc OpenAPI UI | springdoc-openapi-starter-webmvc-ui | **2.6.0** | `org.springdoc:springdoc-openapi-starter-webmvc-ui:2.6.0` | Auto-generate OpenAPI 3.1 spec + Swagger UI from Spring MVC annotations |
| SpringDoc Gradle | springdoc-openapi-gradle-plugin | **2.6.0** | `org.springdoc:springdoc-openapi-gradle-plugin` | Generate `openapi.json` at build time (no running server needed) |
| OpenAPI to AsciiDoc | swagger2markup | **1.3.7** | `io.github.swagger2markup:swagger2markup:1.3.7` | Convert OpenAPI 3.x JSON/YAML spec → AsciiDoc for offline docs |
| Redoc | Redoc CLI | **2.3.x** | npm: `@redocly/cli` | Beautiful OpenAPI HTML docs from `openapi.json`; use in CI/CD |

---

### 16D. DOCUMENTATION OUTPUT FORMATS & THEMES

| Component | Technology | Version | Purpose |
|---|---|---|---|
| AsciiDoc HTML5 | Asciidoctor built-in backend | 3.2.0 | Default HTML5 output; RA operator manual, architecture docs |
| AsciiDoc PDF | AsciidoctorJ PDF | **2.3.19** | PDF output for compliance reports, key ceremony procedures, runbooks |
| Antora | Antora (multi-repo docs site) | **3.2.1** | Publish versioned RA documentation site from Git; component-based |
| Antora Default UI | antora-default-ui | **1.0.x** | Pre-built Antora UI theme |
| PlantUML | PlantUML (via asciidoctorj-diagram) | **1.2025.x** | Architecture diagrams, sequence diagrams, RA workflow FSM diagrams |
| Mermaid | Mermaid (via Kroki) | **11.x** | ER diagrams, flowcharts, Git graphs embedded in AsciiDoc |
| Kroki | Kroki (diagram rendering service) | **0.25.x** | Self-hosted diagram server for PlantUML/Mermaid in CI/CD |

---

### 16E. DOCUMENTATION STRUCTURE FOR RA SYSTEM

```
docs/
├── src/
│   ├── index.adoc                    ← Master document
│   ├── architecture/
│   │   ├── overview.adoc             ← System architecture (PlantUML diagrams)
│   │   ├── tech-stack.adoc           ← This document (auto-included)
│   │   └── data-model.adoc           ← PostgreSQL schema (Mermaid ERD)
│   ├── api/
│   │   ├── est-api.adoc              ← EST endpoints (REST Docs snippets)
│   │   ├── scep-api.adoc             ← SCEP endpoints
│   │   ├── ocsp-api.adoc             ← OCSP responder
│   │   └── operator-api.adoc         ← Operator REST API
│   ├── operations/
│   │   ├── key-ceremony.adoc         ← HSM key ceremony procedure
│   │   ├── runbook.adoc              ← Ops runbook
│   │   └── compliance.adoc           ← FIPS/eIDAS compliance checklist
│   └── security/
│       └── hardening.adoc            ← Security hardening guide
└── pom.xml                           ← asciidoctor-maven-plugin 3.2.0
```

---

### 16F. ASCIIDOCTOR MAVEN PLUGIN CONFIGURATION

```xml
<!-- pom.xml — AsciiDoctor documentation build -->
<plugin>
    <groupId>org.asciidoctor</groupId>
    <artifactId>asciidoctor-maven-plugin</artifactId>
    <version>3.2.0</version>
    <dependencies>
        <!-- PDF backend -->
        <dependency>
            <groupId>org.asciidoctor</groupId>
            <artifactId>asciidoctorj-pdf</artifactId>
            <version>2.3.19</version>
        </dependency>
        <!-- Diagram support (PlantUML, Mermaid) -->
        <dependency>
            <groupId>org.asciidoctor</groupId>
            <artifactId>asciidoctorj-diagram</artifactId>
            <version>2.3.1</version>
        </dependency>
        <!-- Spring REST Docs snippets integration -->
        <dependency>
            <groupId>org.springframework.restdocs</groupId>
            <artifactId>spring-restdocs-asciidoctor</artifactId>
            <version>4.0.0</version>
        </dependency>
    </dependencies>
    <executions>
        <!-- HTML5 output -->
        <execution>
            <id>generate-html-docs</id>
            <phase>prepare-package</phase>
            <goals><goal>process-asciidoc</goal></goals>
            <configuration>
                <backend>html5</backend>
                <attributes>
                    <snippets>${project.build.directory}/generated-snippets</snippets>
                    <toc>left</toc>
                    <icons>font</icons>
                    <sectanchors>true</sectanchors>
                </attributes>
            </configuration>
        </execution>
        <!-- PDF output -->
        <execution>
            <id>generate-pdf-docs</id>
            <phase>prepare-package</phase>
            <goals><goal>process-asciidoc</goal></goals>
            <configuration>
                <backend>pdf</backend>
                <attributes>
                    <pdf-theme>default-with-font-awesome</pdf-theme>
                </attributes>
            </configuration>
        </execution>
    </executions>
</plugin>
```

---

### 16G. DOCUMENTATION VERSION MANIFEST

| Artifact | Group ID | Version |
|---|---|---|
| `asciidoctor-maven-plugin` | `org.asciidoctor` | **3.2.0** |
| `asciidoctorj` | `org.asciidoctor` | **3.0.0** |
| `asciidoctorj-pdf` | `org.asciidoctor` | **2.3.19** |
| `asciidoctorj-diagram` | `org.asciidoctor` | **2.3.1** |
| `asciidoctorj-epub3` | `org.asciidoctor` | **2.1.3** |
| `spring-restdocs-core` | `org.springframework.restdocs` | **4.0.0** |
| `spring-restdocs-asciidoctor` | `org.springframework.restdocs` | **4.0.0** |
| `spring-restdocs-mockmvc` | `org.springframework.restdocs` | **4.0.0** |
| `springdoc-openapi-starter-webmvc-ui` | `org.springdoc` | **2.6.0** |
| `antora` | npm: `@antora/cli` | **3.2.1** |
| `plantuml` | via `asciidoctorj-diagram` | **1.2025.x** |

---

## COMPLETE DEPENDENCY VERSION MANIFEST (pom.xml)

```xml
<properties>
    <!-- ===== RUNTIME ===== -->
    <!-- Spring Boot 4.0.3 released Feb 2026 | Spring Framework 7.0.6 released Mar 2026 -->
    <!-- Upgrade path: 3.3.x → 3.5.x → 4.0.x (do NOT skip 3.5) -->
    <java.version>21</java.version>
    <spring-boot.version>4.0.3</spring-boot.version>           <!-- Feb 19, 2026 -->
    <spring-framework.version>7.0.6</spring-framework.version>  <!-- Mar 13, 2026 -->
    <spring-security.version>7.0.x</spring-security.version>    <!-- Aligned with Spring Boot 4.0 -->
    <spring-statemachine.version>3.2.1</spring-statemachine.version>
    <spring-cloud.version>2025.0.x</spring-cloud.version>        <!-- Spring Boot 4.0 compatible BOM -->
    <spring-vault.version>3.1.2</spring-vault.version>
    <spring-ldap.version>3.2.4</spring-ldap.version>
    <spring-kafka.version>3.3.x</spring-kafka.version>           <!-- Aligned with Spring Boot 4.0 -->
    <spring-batch.version>5.2.x</spring-batch.version>           <!-- Aligned with Spring Boot 4.0 -->
    <!-- Build tools -->
    <!-- gradle.version>9.4.0</gradle.version -->                <!-- Mar 4, 2026 — use wrapper -->

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

    <!-- ===== TESTING (see Sections 14 & 15 for full Spring Boot Test stack) ===== -->
    <spring-boot-test.version>4.0.3</spring-boot-test.version>
    <spring-security-test.version>7.0.x</spring-security-test.version>
    <junit6.version>6.0.3</junit6.version>                    <!-- Feb 15, 2026 — current gen -->
    <junit5.version>5.13.4</junit5.version>                    <!-- Latest JUnit 5.x LTS fallback -->
    <mockito.version>5.23.0</mockito.version>                  <!-- Mar 11, 2026 -->
    <assertj.version>3.27.7</assertj.version>                  <!-- Jan 2026 — CVE patched -->
    <testcontainers.version>1.20.2</testcontainers.version>
    <wiremock.version>3.9.1</wiremock.version>
    <rest-assured.version>5.5.0</rest-assured.version>
    <datafaker.version>2.4.2</datafaker.version>
    <instancio.version>5.3.0</instancio.version>
    <awaitility.version>4.2.2</awaitility.version>
    <jmh.version>1.37</jmh.version>
    <jacoco.version>0.8.12</jacoco.version>
    <pitest.version>1.17.1</pitest.version>
    <spotbugs.version>4.8.6</spotbugs.version>
    <owasp-dep-check.version>10.0.4</owasp-dep-check.version>
    <!-- ===== DOCUMENTATION (see Section 16 for full AsciiDoctor stack) ===== -->
    <asciidoctor-maven-plugin.version>3.2.0</asciidoctor-maven-plugin.version>
    <asciidoctorj.version>3.0.0</asciidoctorj.version>
    <asciidoctorj-pdf.version>2.3.19</asciidoctorj-pdf.version>
    <asciidoctorj-diagram.version>2.3.1</asciidoctorj-diagram.version>
    <spring-restdocs.version>4.0.0</spring-restdocs.version>
    <springdoc-openapi.version>2.6.0</springdoc-openapi.version>
</properties>
```

---

*PKI Architecture Team | Confidential — Internal Use Only | Next Review: 2026-09-14*
