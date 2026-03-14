# Registration Authority (RA) System — Technology Stack Reference Tables
**Version:** 2.1 | **Date:** 2026-03-14 | **Project:** PKI Registration Authority
**Base:** Java 21 LTS + Spring Boot 4.0.3 + Spring Framework 7.0.6 + Gradle 9.4.0

> ⚠️ **Migration Note:** Spring Boot 4.0 requires Java 17 minimum (Java 21 recommended). Upgrade path: `3.3.x → 3.5.x → 4.0.x`. Spring Framework 7.0 is the aligned core framework.

---

## 1. CORE TECHNOLOGY STACK

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| JDK Runtime | Eclipse Temurin (OpenJDK) | **21.0.3 LTS** | Primary Java runtime; Virtual Threads (Project Loom), ZGC garbage collector, long-term support until 2029 |
| Application Framework | Spring Boot | **4.0.3** *(Feb 2026)* | Auto-configuration, embedded Tomcat 11, production-ready starter POMs; JSpecify null-safety, API Versioning, Java 25 support |
| Core Framework | Spring Framework | **7.0.6** *(Mar 2026)* | Dependency injection, AOP, AOT compilation, virtual thread executor; Jakarta EE 11, JSpecify null annotations |
| Web Layer | Spring Web MVC | **7.0.6** *(Mar 2026)* | REST controllers, EST/SCEP/CMP/ACME protocol endpoint handling; multiple-view-per-request support |
| Build Tool | Gradle | **9.4.0** *(Mar 2026)* | **Primary build system**; Kotlin DSL (`build.gradle.kts`), multi-module support, Java 26, stable task graph, Spring Boot 4.0 plugin compatible |
| Build Tool Wrapper | Gradle Wrapper (`gradlew`) | **9.4.0** | `./gradlew build` — reproducible builds; no system Gradle install required |
| API Gateway | Spring Cloud Gateway | **4.2.x** *(2025.0.x BOM)* | Request routing, rate limiting, mTLS termination, circuit breaker; Spring Boot 4.0 aligned |
| Workflow Engine | Spring State Machine | **3.2.1** | Certificate request lifecycle FSM (Submitted → Validated → Approved → Issued) |
| Async Processing | Spring Async + Virtual Threads | **JDK 21 built-in** | High-throughput non-blocking certificate request processing |
| REST Documentation | SpringDoc OpenAPI (Swagger UI) | **2.6.0** | Auto-generated API docs from annotations |
| Input Validation | Hibernate Validator (Jakarta) | **8.0.1.Final** | Bean validation for CSR fields, DN patterns, profile constraints |
| JSON Serialization | Jackson Databind | **2.17.2** | REST payload serialization/deserialization |
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
| Multiple CA Support | CA Connector abstraction interface | Custom impl | Pluggable `CaConnector` interface; supports EJBCA, MS ADCS |
| Certificate Profiles | EJBCA profile management | **8.3.x** | TLS/SSL, S/MIME, Code Signing, Client Auth, IoT Device profiles |
| MS ADCS Integration | Microsoft ADCS via CEP/CES | Windows Server 2022 | Optional: enterprise Windows environments using MS PKI |

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
| Checkstyle | Checkstyle + Gradle plugin | **10.18.x** | `checkstyle { toolVersion = "10.18.x" }` in `build.gradle.kts`; enforce PKI team coding standards |
| SpotBugs | SpotBugs + Find Security Bugs | **4.8.6** | `id("com.github.spotbugs") version "6.x"` Gradle plugin; detect `HARD_CODE_KEY`, `WEAK_CIPHER` |
| OWASP Dependency Check | OWASP Dependency-Check Gradle | **10.0.4** | `id("org.owasp.dependencycheck")` Gradle plugin; scan `build.gradle.kts` deps for CVEs; fail on CVSS ≥ 7 |

---

### 14I. COMPLETE TEST DEPENDENCY MANIFEST (build.gradle.kts)

```kotlin
// ===== SPRING BOOT TEST STACK — build.gradle.kts =====

dependencies {

    // Master test starter — JUnit 6, Mockito 5.23, AssertJ 3.27.7,
    // Hamcrest, JSONAssert, JsonPath, Awaitility included transitively
    testImplementation("org.springframework.boot:spring-boot-starter-test:4.0.3")

    // Spring Security Test — @WithMockUser, x509(), jwt() post-processors
    testImplementation("org.springframework.security:spring-security-test:7.0.x")

    // Testcontainers BOM — real PostgreSQL, Redis, Kafka, Keycloak, Vault
    testImplementation(platform("org.testcontainers:testcontainers-bom:1.20.2"))
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("org.testcontainers:kafka")
    testImplementation("com.redis:testcontainers-redis:2.2.2")

    // WireMock — mock EJBCA CMP/REST, OCSP, CT log endpoints
    testImplementation("org.wiremock:wiremock:3.9.1")

    // REST-assured — fluent HTTP integration test DSL
    testImplementation("io.rest-assured:rest-assured:5.5.0")

    // JMH — microbenchmark crypto & HSM signing operations
    testImplementation("org.openjdk.jmh:jmh-core:1.37")
    testAnnotationProcessor("org.openjdk.jmh:jmh-generator-annprocess:1.37")

    // Bouncy Castle — PKI test data: generate CA, CSRs, test cert chains
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

// Gradle Test Task — JUnit Platform configuration
tasks.test {
    useJUnitPlatform()
    jvmArgs("-Dspring.profiles.active=test")
    maxParallelForks = Runtime.getRuntime().availableProcessors()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}
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

| Component | Technology | Version (Latest) | Gradle Artifact | Purpose |
|---|---|---|---|---|
| JUnit 6 Engine | JUnit Jupiter | **6.0.3** *(Feb 2026)* | `testImplementation("org.junit.jupiter:junit-jupiter:6.0.3")` | Current generation test runner; Java 17+ required; `@Test`, `@Nested`, `@DisplayName` |
| JUnit 5 Engine | JUnit Jupiter (5.x LTS) | **5.13.4** | `testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")` | LTS fallback if Spring Boot BOM still on 5.x |
| JUnit Platform | JUnit Platform Launcher | **1.13.4** | `testRuntimeOnly("org.junit.platform:junit-platform-launcher")` | Test discovery, filtering, engine execution |
| JUnit Platform Suite | JUnit Platform Suite | **1.13.4** | `testImplementation("org.junit.platform:junit-platform-suite")` | `@Suite`, `@SelectPackages` — aggregate test suites |
| Gradle Test Task | Gradle Test (built-in) | **9.4.0** | `tasks.test { useJUnitPlatform() }` in `build.gradle.kts` | Run JUnit 6 tests with `./gradlew test`; JUnit Platform native support |
| Gradle Test Report | HTML Test Report (built-in) | **9.4.0** | Built-in | `build/reports/tests/test/index.html` — full test result HTML report |
| JUnit Vintage | JUnit Vintage Engine | **5.13.4** | `testRuntimeOnly("org.junit.vintage:junit-vintage-engine")` | Run legacy JUnit 4 tests in JUnit 5/6 platform |

---

### 15B. MOCKITO — MOCKING FRAMEWORK

| Component | Technology | Version (Latest) | Gradle Artifact | Purpose |
|---|---|---|---|---|
| Mockito Core | Mockito | **5.23.0** *(Mar 2026)* | `testImplementation("org.mockito:mockito-core:5.23.0")` | Core mocking framework; `mock()`, `when()`, `verify()`, `spy()` |
| Mockito JUnit Jupiter | Mockito JUnit Jupiter Extension | **5.23.0** | `testImplementation("org.mockito:mockito-junit-jupiter:5.23.0")` | `@ExtendWith(MockitoExtension.class)` — auto inject `@Mock`, `@InjectMocks` |
| Mockito Inline | Mockito Inline (default in 5.x) | **5.23.0** | Built into `mockito-core` 5.x | Mock `final` classes, `static` methods, constructors; default mock maker |
| Spring MockBean | `@MockBean` / `@SpyBean` | **4.0.3** *(SB 4.0)* | `testImplementation("org.springframework.boot:spring-boot-test:4.0.3")` | Replace Spring beans in `ApplicationContext` with Mockito mocks |
| Mockito Kotlin | mockito-kotlin | **6.2.3** | `testImplementation("org.mockito.kotlin:mockito-kotlin:6.2.3")` | Kotlin-friendly Mockito DSL (if Kotlin used in RA tests) |

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

| Component | Technology | Version (Latest) | Gradle Artifact | Purpose |
|---|---|---|---|---|
| AssertJ Core | AssertJ | **3.27.7** *(Jan 2026)* | `testImplementation("org.assertj:assertj-core:3.27.7")` | Fluent, type-safe assertions; CVE-2026-24400 XXE fix included |
| AssertJ DB | AssertJ-DB | **3.0.0** | `testImplementation("org.assertj:assertj-db:3.0.0")` | Assert database state — verify rows in `certificate_requests` table |
| Hamcrest | Hamcrest | **2.2** | `testImplementation("org.hamcrest:hamcrest:2.2")` | Matcher-based assertions; used in MockMvc `andExpect(jsonPath(..., is(...)))` |
| JSONAssert | JSONAssert | **1.5.3** | `testImplementation("org.skyscreamer:jsonassert:1.5.3")` | Compare JSON responses; `strict` mode for REST API contract validation |
| JsonPath | Jayway JsonPath | **2.9.0** | `testImplementation("com.jayway.jsonpath:json-path:2.9.0")` | Extract values from JSON response: `$.request.status`, `$.certificates[0].serial` |
| Truth | Google Truth | **1.4.4** | `testImplementation("com.google.truth:truth:1.4.4")` | Alternative fluent assertion library from Google |

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

| Component | Technology | Version (Latest) | Gradle Artifact | Purpose |
|---|---|---|---|---|
| Asciidoctor Gradle Plugin | asciidoctor-gradle-jvm | **4.0.3** | `id("org.asciidoctor.jvm.convert") version "4.0.3"` | **Primary tool** — convert `.adoc` → HTML5 / PDF / DocBook via Gradle task |
| Asciidoctor Gradle PDF | asciidoctor-gradle-jvm (PDF) | **4.0.3** | `id("org.asciidoctor.jvm.pdf") version "4.0.3"` | Dedicated Gradle plugin for PDF output |
| AsciidoctorJ | AsciidoctorJ | **3.0.0** | `asciidoctorj { version = "3.0.0" }` in `build.gradle.kts` | Java API wrapping Asciidoctor (JRuby-based); auto-resolved by Gradle plugin |
| AsciidoctorJ PDF | asciidoctorj-pdf | **2.3.19** | `org.asciidoctor:asciidoctorj-pdf:2.3.19` | Generate PDF output from `.adoc` — RA architecture docs, runbooks |
| AsciidoctorJ EPUB3 | asciidoctorj-epub3 | **2.1.3** | `org.asciidoctor:asciidoctorj-epub3:2.1.3` | Generate EPUB3 e-book format from AsciiDoc |
| Asciidoctor Diagram | asciidoctorj-diagram | **2.3.1** | `org.asciidoctor:asciidoctorj-diagram:2.3.1` | Render PlantUML, Mermaid, C4 diagrams inline in AsciiDoc |

---

### 16B. SPRING REST DOCS + ASCIIDOCTOR *(API Documentation from Tests)*

| Component | Technology | Version (Latest) | Gradle Artifact | Purpose |
|---|---|---|---|---|
| Spring REST Docs Core | spring-restdocs-core | **4.0.0** | `testImplementation("org.springframework.restdocs:spring-restdocs-core:4.0.0")` | Generate documentation snippets from MockMvc / WebTestClient tests |
| Spring REST Docs AsciiDoctor | spring-restdocs-asciidoctor | **4.0.0** | `asciidoctorExtensions("org.springframework.restdocs:spring-restdocs-asciidoctor:4.0.0")` | AsciidoctorJ 3.0 extension; include auto-generated snippets in `.adoc` files |
| Spring REST Docs MockMvc | spring-restdocs-mockmvc | **4.0.0** | `testImplementation("org.springframework.restdocs:spring-restdocs-mockmvc:4.0.0")` | Document EST `/simpleenroll`, OCSP, CRL endpoints via MockMvc tests |
| Spring REST Docs WebTestClient | spring-restdocs-webtestclient | **4.0.0** | `testImplementation("org.springframework.restdocs:spring-restdocs-webtestclient:4.0.0")` | Document reactive RA endpoints via `WebTestClient` |
| Spring Auto REST Docs | spring-auto-restdocs | **2.0.11** | `testImplementation("capital.scalable:spring-auto-restdocs-core:2.0.11")` | Auto-document request/response fields from Jackson + JavaDoc |

**Spring REST Docs flow:**
```
MockMvc Test → REST Docs Snippets (.adoc) → Asciidoctor Maven Plugin → HTML5 / PDF API Docs
```

---

### 16C. OPENAPI / SWAGGER DOCUMENTATION

| Component | Technology | Version (Latest) | Gradle Artifact | Purpose |
|---|---|---|---|---|
| SpringDoc OpenAPI UI | springdoc-openapi-starter-webmvc-ui | **2.6.0** | `implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.6.0")` | Auto-generate OpenAPI 3.1 spec + Swagger UI from Spring MVC annotations |
| SpringDoc Gradle Plugin | springdoc-openapi-gradle-plugin | **2.6.0** | `id("org.springdoc.openapi-gradle-plugin") version "2.6.0"` | Generate `openapi.json` at build time via `./gradlew generateOpenApiDocs` |
| OpenAPI to AsciiDoc | swagger2markup | **1.3.7** | `implementation("io.github.swagger2markup:swagger2markup:1.3.7")` | Convert OpenAPI 3.x JSON/YAML spec → AsciiDoc for offline docs |
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
└── build.gradle.kts                  ← asciidoctor-gradle-jvm 4.0.3
```

---

### 16F. ASCIIDOCTOR GRADLE PLUGIN CONFIGURATION (build.gradle.kts)

```kotlin
// build.gradle.kts — AsciiDoctor documentation build

plugins {
    id("org.asciidoctor.jvm.convert") version "4.0.3"   // HTML5 output
    id("org.asciidoctor.jvm.pdf")     version "4.0.3"   // PDF output
}

// AsciidoctorJ core version + extensions
asciidoctorj {
    version = "3.0.0"
    modules {
        diagram.use()                         // PlantUML + Mermaid diagrams
        diagram.version("2.3.1")
        pdf.version("2.3.19")
    }
}

// Asciidoctor configuration — REST Docs snippets extension
configurations {
    create("asciidoctorExtensions")
}

dependencies {
    // Spring REST Docs Asciidoctor extension (snippets include macro)
    "asciidoctorExtensions"(
        "org.springframework.restdocs:spring-restdocs-asciidoctor:4.0.0"
    )
}

// HTML5 output task
tasks.asciidoctor {
    configurations("asciidoctorExtensions")
    dependsOn(tasks.test)                    // Run tests first to generate snippets
    baseDirFollowsSourceDir()
    attributes(mapOf(
        "snippets"   to file("${layout.buildDirectory.get()}/generated-snippets"),
        "toc"        to "left",
        "icons"      to "font",
        "sectanchors" to "true",
        "source-highlighter" to "rouge"
    ))
    outputOptions {
        backends("html5")
    }
}

// PDF output task
tasks.asciidoctorPdf {
    configurations("asciidoctorExtensions")
    dependsOn(tasks.test)
    attributes(mapOf(
        "pdf-theme" to "default-with-font-awesome",
        "snippets"  to file("${layout.buildDirectory.get()}/generated-snippets")
    ))
}

// Include docs in final JAR
tasks.bootJar {
    dependsOn(tasks.asciidoctor)
    from("${tasks.asciidoctor.get().outputDir}") {
        into("BOOT-INF/classes/static/docs")
    }
}
```

---

### 16G. DOCUMENTATION VERSION MANIFEST

| Artifact | Group ID | Version |
|---|---|---|
| `asciidoctor-gradle-jvm` (Gradle plugin) | `org.asciidoctor` | **4.0.3** |
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

## 17. OBSERVABILITY & METRICS TECH STACK *(Spring Boot 4.0 Compatible)*

> Spring Boot 4.0 renames observability modules and introduces a new `spring-boot-starter-opentelemetry`.
> Micrometer 1.16.x is the aligned version for Spring Boot 4.0.x

---

### 17A. SPRING BOOT ACTUATOR & MICROMETER

| Component | Technology | Version (Latest) | Maven Artifact | Purpose |
|---|---|---|---|---|
| Spring Boot Actuator | `spring-boot-starter-actuator` | **4.0.3** | `org.springframework.boot:spring-boot-starter-actuator` | Exposes `/actuator/health`, `/actuator/metrics`, `/actuator/info`, `/actuator/prometheus` |
| Micrometer Core | Micrometer | **1.16.x** *(SB 4.0 aligned)* | `io.micrometer:micrometer-core:1.16.x` | Metrics facade — `Counter`, `Timer`, `Gauge`, `DistributionSummary` for RA business metrics |
| Micrometer Prometheus | Micrometer Registry Prometheus | **1.16.x** | `io.micrometer:micrometer-registry-prometheus:1.16.x` | Expose metrics in Prometheus scrape format at `/actuator/prometheus` |
| Micrometer Tracing | Micrometer Tracing | **1.6.x** | `io.micrometer:micrometer-tracing:1.6.x` | Distributed tracing bridge; `@Observed`, `@WithSpan` on cert issuance methods |
| Micrometer Observation | `spring-boot-micrometer-observation` | **4.0.3** | Built into SB 4.0 | *(Renamed from `spring-boot-observation` in SB 4.0)* — `ObservationRegistry` |
| Micrometer OTel Bridge | `micrometer-tracing-bridge-otel` | **1.6.x** | `io.micrometer:micrometer-tracing-bridge-otel` | Connect Micrometer Tracing → OpenTelemetry SDK for trace export |
| Datasource Micrometer | datasource-micrometer | **1.0.6** | `net.ttddyy.observation:datasource-micrometer-spring-boot` | JDBC query metrics and tracing — monitor PostgreSQL query times |
| Spring Boot OTel Starter | `spring-boot-starter-opentelemetry` | **4.0.3** *(NEW in SB 4.0)* | `org.springframework.boot:spring-boot-starter-opentelemetry` | All-in-one OpenTelemetry starter — OTLP export of metrics, traces, logs |

**Key RA Custom Metrics (Micrometer):**

| Metric Name | Type | Tags | Purpose |
|---|---|---|---|
| `ra.cert.requests.total` | Counter | `protocol`, `profile`, `status` | Total certificate requests by protocol/status |
| `ra.cert.issuance.duration` | Timer | `profile` | Certificate issuance latency histogram |
| `ra.hsm.operations.total` | Counter | `operation`, `result` | HSM sign/verify operation counts |
| `ra.ocsp.requests.total` | Counter | `status` | OCSP responder request counts |
| `ra.csr.validation.failures` | Counter | `reason` | CSR validation failure breakdown |
| `ra.approval.queue.size` | Gauge | — | Pending approval queue depth |
| `ra.cert.expiry.days` | Gauge | `serial`, `profile` | Days until certificate expiry (alert < 30) |
| `ra.revocations.total` | Counter | `reason` | Revocations by reason code |

---

### 17B. OPENTELEMETRY (TRACES, METRICS, LOGS)

| Component | Technology | Version (Latest) | Maven / Download | Purpose |
|---|---|---|---|---|
| OTel Java Agent | opentelemetry-javaagent | **1.60.1** *(Mar 2026)* | `io.opentelemetry.javaagent:opentelemetry-javaagent:1.60.1` | Zero-code auto-instrumentation; attach via `-javaagent:otel-agent.jar` |
| OTel SDK | opentelemetry-sdk | **1.60.1** | `io.opentelemetry:opentelemetry-sdk:1.60.1` | Manual instrumentation SDK for custom spans in HSM operations |
| OTel API | opentelemetry-api | **1.60.1** | `io.opentelemetry:opentelemetry-api:1.60.1` | API-only dependency for library code |
| OTel Spring Boot | `spring-boot-starter-opentelemetry` | **4.0.3** | Built into Spring Boot 4.0 | OTLP metric/trace/log export; replaces manual OTel wiring |
| OTLP Exporter | opentelemetry-exporter-otlp | **1.60.1** | `io.opentelemetry:opentelemetry-exporter-otlp` | Export traces → Grafana Tempo; metrics → Grafana Mimir |
| Grafana Alloy | Grafana Alloy | **1.6.x** | `grafana/alloy` Docker | OpenTelemetry Collector replacement; route OTel signals to backends |

---

### 17C. METRICS BACKEND (PROMETHEUS + GRAFANA)

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Prometheus | Prometheus | **3.10.0** *(Feb 2026)* | Time-series metrics storage; scrape `/actuator/prometheus` every 15s |
| Grafana | Grafana | **12.3** *(2026)* | Dashboards, alerting, log/trace/metric correlation; RA KPI dashboards |
| Grafana Mimir | Grafana Mimir | **2.14.x** | Long-term metrics storage (scalable Prometheus); multi-tenant |
| Prometheus Alertmanager | Alertmanager | **0.27.x** | Route alerts → PagerDuty, Slack, email on HSM failure / cert spike |
| kube-prometheus-stack | Helm chart | **65.x** | All-in-one Prometheus + Grafana + Alertmanager for Kubernetes |
| node-exporter | Prometheus Node Exporter | **1.8.x** | Host-level CPU, memory, disk metrics for RA nodes |
| jmx-exporter | JMX Exporter | **1.1.x** | Expose JVM / Tomcat JMX metrics to Prometheus (fallback) |

---

### 17D. LOG AGGREGATION (GRAFANA LOKI STACK)

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Grafana Loki | Loki | **3.6.7** *(Feb 2026)* | Log aggregation backend; label-based indexing optimized for Kubernetes |
| Grafana Alloy | Alloy (OTel Collector) | **1.6.x** | Ship logs from K8s pods → Loki; replaces Promtail |
| Promtail | Promtail (legacy shipper) | **3.6.7** | K8s log shipper for Loki (use Alloy for new deployments) |
| Logback Encoder | Logstash Logback Encoder | **7.4** | JSON structured logs; adds `traceId`, `spanId`, `requestId` MDC fields |
| Logback Loki Appender | `loki4j-logback-appender` | **1.5.2** | Push logs directly from Spring Boot → Loki without Alloy (dev env) |
| Elasticsearch (alt) | Elasticsearch | **8.15.2** | Alternative log store for full-text search; use if SIEM requires ELK |
| Kibana (alt) | Kibana | **8.15.2** | Log visualization UI for Elasticsearch backend |

---

### 17E. DISTRIBUTED TRACING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Grafana Tempo | Grafana Tempo | **2.7.x** | Distributed trace storage; integrates with Grafana for trace-to-log correlation |
| Micrometer Tracing | Micrometer Tracing (OTel bridge) | **1.6.x** | `@Observed` on `issueCertificate()`, `validateCsr()` — auto-span creation |
| OTel Java Agent | opentelemetry-javaagent | **1.60.1** | Auto-instrument Spring MVC, JDBC, Kafka, Redis, HTTP clients |
| Jaeger (alt) | Jaeger | **2.2.x** | Alternative trace backend; use if already deployed in enterprise |
| Zipkin (alt) | Zipkin | **3.4.x** | Lightweight alternative trace backend |

---

### 17F. HEALTH CHECKS & ALERTING

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Spring Boot Actuator Health | Built-in | **4.0.3** | `/actuator/health/liveness` + `/actuator/health/readiness` for K8s probes |
| Custom Health Indicators | `HealthIndicator` interface | **4.0.3** | `HsmHealthIndicator`, `CaConnectorHealthIndicator`, `immudbHealthIndicator` |
| Grafana Alerting | Grafana Alerting | **12.3** | Unified alerting engine; rules defined in Grafana or `alert.rules.yaml` |
| Alertmanager | Prometheus Alertmanager | **0.27.x** | Route alerts → PagerDuty / Slack / email by severity |
| PagerDuty Integration | PagerDuty Events API v2 | **v2** | On-call escalation for `CRITICAL` HSM failure, cert issuance anomaly |
| Grafana OnCall | Grafana OnCall | **1.9.x** | On-call scheduling integrated with Grafana dashboards |

---

### 17G. SPRING BOOT 4.0 OBSERVABILITY — MODULE RENAME MAP

> ⚠️ Spring Boot 4.0 renames observability auto-configuration modules:

| Old Name (SB 3.x) | New Name (SB 4.0) | Root Package Change |
|---|---|---|
| `spring-boot-metrics` | `spring-boot-micrometer-metrics` | `...micrometer.metrics` |
| `spring-boot-observation` | `spring-boot-micrometer-observation` | `...micrometer.observation` |
| `spring-boot-tracing` | `spring-boot-micrometer-tracing` | `...micrometer.tracing` |
| Manual OTel setup | `spring-boot-starter-opentelemetry` | New unified starter |

---

### 17H. OBSERVABILITY VERSION MANIFEST

| Artifact | Version |
|---|---|
| `spring-boot-starter-actuator` | **4.0.3** |
| `micrometer-core` | **1.16.x** |
| `micrometer-registry-prometheus` | **1.16.x** |
| `micrometer-tracing` | **1.6.x** |
| `micrometer-tracing-bridge-otel` | **1.6.x** |
| `spring-boot-starter-opentelemetry` | **4.0.3** |
| `opentelemetry-javaagent` | **1.60.1** |
| `opentelemetry-sdk` | **1.60.1** |
| `logstash-logback-encoder` | **7.4** |
| `loki4j-logback-appender` | **1.5.2** |
| Prometheus (server) | **3.10.0** |
| Grafana (server) | **12.3** |
| Grafana Loki (server) | **3.6.7** |
| Grafana Tempo (server) | **2.7.x** |
| Grafana Mimir (server) | **2.14.x** |
| Grafana Alloy (collector) | **1.6.x** |

---

## 18. IMMUTABLE LOGS TECH STACK *(Spring Boot 4.0 Compatible)*

> PKI/RA systems require **tamper-evident, legally defensible audit logs**.
> This section covers the complete immutable log stack — from append-only stores
> to hash-chained databases and cryptographic log signing, all integrated with Spring Boot 4.0.

---

### 18A. IMMUTABLE / APPEND-ONLY LOG STORES

| Component | Technology | Version (Latest) | Maven Artifact | Purpose |
|---|---|---|---|---|
| **immudb** | immudb (primary choice) | **1.9.5** | Server: Docker `codenotary/immudb:1.9.5` | Cryptographically verifiable, tamper-evident database; `verifiedSet` / `verifiedGet` throws on tampering |
| immudb Java Client | immudb4j | **1.0.1** | `io.codenotary:immudb4j:1.0.1` | Java SDK; Spring Boot 4.0 compatible via `@Bean` config |
| immudb Spring Boot | Custom Spring `@Configuration` | Custom | N/A — manual `ImmuClient` bean wiring | Wire `ImmuClient` as Spring bean; `@Transactional`-like audit pattern |
| Azure Immutable Blob | Azure Blob WORM (Time-based retention) | **Latest** | `com.azure:azure-storage-blob:12.x` | Azure write-once-read-many blob for log archival |

---

### 18B. HASH-CHAINED AUDIT LOGGING (POSTGRESQL)

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| PostgreSQL Audit Table | PostgreSQL + `audit_events` table | **16.4** | Relational audit store with `prev_hash` + `event_hash` columns; chain verified on read |
| Hash Algorithm | SHA-256 (via BC FIPS) | BC FIPS **2.0.0** | `SHA256(prev_hash \|\| event_type \|\| actor \|\| timestamp \|\| data)` per row |
| Hash Chain Verifier | Custom Spring Service | Spring Boot **4.0.3** | `AuditChainVerifierService` — walks entire chain; throws `ChainBrokenException` on tampering |
| Spring Data JPA | Hibernate ORM | **6.5.3.Final** | Persist `AuditEvent` entities; `@EntityListeners(AuditListener.class)` |
| `@PrePersist` Hook | Spring JPA Lifecycle | **4.0.3 / 6.5.x** | Compute `event_hash` before INSERT; chain to previous record's hash |
| Flyway | Flyway | **10.18.0** | Migration script creates `audit_events` table with hash columns and index |

**Hash Chain Schema:**
```sql
CREATE TABLE audit_events (
    id              BIGSERIAL     PRIMARY KEY,
    event_id        UUID          UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    event_type      VARCHAR(64)   NOT NULL,     -- CERT_ISSUED, CERT_REVOKED, OPERATOR_LOGIN
    actor           VARCHAR(256)  NOT NULL,     -- operator DN or subscriber DN
    resource_id     VARCHAR(128),               -- certificate serial number
    event_data      JSONB,                      -- full event payload
    ip_address      INET,
    event_time      TIMESTAMPTZ   DEFAULT NOW(),
    prev_hash       CHAR(64),                   -- SHA-256 of previous row
    event_hash      CHAR(64)      NOT NULL      -- SHA-256(prev_hash||event_type||actor||time||data)
);
```

---

### 18C. SPRING BOOT AUDIT LOGGING INTEGRATION

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Spring Data Auditing | `@EnableJpaAuditing` | **4.0.3** | Auto-populate `@CreatedDate`, `@CreatedBy`, `@LastModifiedDate` on entities |
| Spring AOP Audit Aspect | Spring AOP (`@Aspect`) | **7.0.6** | `@Around` advice on `@AuditLog` annotated methods — capture before/after state |
| Spring Events | `ApplicationEventPublisher` | **7.0.6** | Publish `CertificateIssuedEvent`, `RevocationRequestedEvent` → async audit handler |
| Spring Async | `@Async` + Virtual Threads | JDK 21 | Non-blocking audit log writes — don't block main request thread |
| Transactional Outbox | PostgreSQL + Spring Scheduler | **4.0.3** | Guaranteed audit event delivery to immudb even on service restart |
| `@TransactionalEventListener` | Spring TX Events | **7.0.6** | Fire audit write AFTER main transaction commits — consistent audit trail |

**Audit Flow:**
```
HTTP Request (EST/SCEP)
    ↓
CertificateRequestService.issue()  ← @AuditLog AOP aspect fires
    ↓
ApplicationEventPublisher.publishEvent(CertificateIssuedEvent)
    ↓ (AFTER_COMMIT via @TransactionalEventListener)
    ├── HashChainAuditService → PostgreSQL audit_events (hash-chained)
    └── ImmudbAuditService    → immudb.verifiedSet(key, value)
                                   ↓
                              Kafka audit-events topic → SIEM
```

---

### 18D. LOG SIGNING & CRYPTOGRAPHIC INTEGRITY

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Log Entry Signing | Bouncy Castle FIPS (ECDSA P-384) | **BC FIPS 2.0.0** | Sign audit log batches with HSM-backed RA signing key every 5 minutes |
| Timestamp Authority | RFC 3161 TSA client (BC) | **BC 1.78.1** | Trusted timestamp on audit log batches; non-repudiation for compliance |
| Merkle Tree Log | Custom implementation | Spring Boot 4.0.3 | Batch audit events into Merkle tree; store root hash in immudb |
| immudb Verified Write | `immuClient.verifiedSet()` | **immudb4j 1.0.1** | Cryptographic proof returned on write; store proof alongside record |
| Log Archive Signing | GPG / minisign | Runtime | Sign archived log files (CRL, OCSP logs) for long-term storage integrity |

---

### 18E. TAMPER-EVIDENT LOG STREAM (KAFKA + SIEM)

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Audit Event Stream | Apache Kafka | **3.8.0** | Real-time audit event stream: `ra.audit.events` topic |
| Spring Kafka Producer | Spring Kafka | **3.3.x** | Publish `AuditEvent` JSON to Kafka after each cert operation |
| Kafka Log Compaction | Kafka built-in | **3.8.0** | Retain all audit events indefinitely (`cleanup.policy=compact,delete`) |
| Kafka TLS | SSL/TLS + mTLS | TLS 1.3 | Encrypt audit event stream in transit; mutual auth between RA and Kafka |
| Splunk Forwarder | Splunk Universal Forwarder | **9.3.0** | Forward Kafka audit stream → Splunk SIEM for SOC monitoring |
| SIEM Integration | IBM QRadar / MS Sentinel (alt) | Latest | Enterprise SIEM integration via Kafka Connect or Splunk |
| Kafka Connect | Confluent Kafka Connect | **7.7.x** | Sink connector: Kafka `ra.audit.events` → Elasticsearch / Splunk |

---

### 18F. COMPLIANCE & LONG-TERM LOG RETENTION

| Component | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Log Retention Policy | PostgreSQL partition + `pg_partman` | **5.1.0** | Monthly partition rotation; archive cold partitions to S3/NAS |
| Audit Archive | S3 / MinIO + WORM policy | Latest | Write-once S3 buckets for 7-year log retention (FIPS/eIDAS requirement) |
| MinIO | MinIO (S3-compatible) | **RELEASE.2026** | On-premises S3-compatible object store with WORM (Object Lock) |
| Log Integrity Check | Scheduled `AuditChainVerifier` | Spring Scheduler | Nightly job: walks entire `audit_events` hash chain; alerts on break |
| Compliance Reports | Spring Batch + JasperReports | **5.2.x / 6.21.3** | Monthly FIPS/eIDAS compliance reports from audit data |
| Log Export API | Spring Boot REST | **4.0.3** | `GET /api/v1/audit/export?from=&to=` — export signed audit log for auditors |

---

### 18G. IMMUTABLE LOG VERSION MANIFEST

| Artifact | Version | Notes |
|---|---|---|
| `immudb` (server) | **1.9.5** | Run via Docker / K8s |
| `immudb4j` | **1.0.1** | `io.codenotary:immudb4j` |
| `micrometer-core` (audit metrics) | **1.16.x** | Count audit writes |
| `spring-kafka` | **3.3.x** | Audit event streaming |
| `kafka` (server) | **3.8.0** | Audit topic broker |
| `postgresql` (audit_events table) | **16.4** | Hash-chained store |
| `flyway` (audit schema) | **10.18.0** | Audit table migration |
| `bc-fips` (log signing) | **2.0.0** | ECDSA P-384 signing |
| `bcprov-jdk18on` (TSA client) | **1.78.1** | RFC 3161 timestamps |
| `pg_partman` | **5.1.0** | Partition management |
| `splunk-universal-forwarder` | **9.3.0** | SIEM integration |

---

## 19. CLIENT TOOLS & DEVELOPER TOOLING

> Developer and operator client tools required to connect to databases, metrics backends,
> HSMs, message brokers, vaults, and other RA system services.

---

### 19A. DATABASE CLIENT TOOLS

| Tool | Technology | Version (Latest) | Platform | Purpose |
|---|---|---|---|---|
| DBeaver | DBeaver Community | **24.2.x** | Windows / Mac / Linux | Universal DB client; connect to PostgreSQL 16 RA database; view `certificate_requests`, `audit_events` |
| pgAdmin 4 | pgAdmin | **8.12** | Web / Desktop | Official PostgreSQL web GUI; query, backup, table management |
| IntelliJ Database Tools | IntelliJ IDEA (built-in) | **2025.x** | IDE | IDE-integrated DB explorer; SQL console for dev-time queries |
| psql | PostgreSQL CLI | **16.4** | CLI | Native PostgreSQL CLI client; scripted DB checks in CI/CD |
| Flyway CLI | Flyway Desktop / CLI | **10.18.0** | CLI | Run schema migrations manually; check migration status |
| DataGrip | DataGrip (JetBrains) | **2025.x** | Desktop | Advanced SQL IDE; ERD diagrams, query analysis |

---

### 19B. METRICS & MONITORING CLIENT TOOLS

| Tool | Technology | Version (Latest) | Access | Purpose |
|---|---|---|---|---|
| Grafana Web UI | Grafana | **12.3** | `https://grafana.ra.internal:3000` | RA KPI dashboards: cert issuance rate, HSM ops, approval queue, OCSP |
| Prometheus Web UI | Prometheus | **3.10.0** | `https://prometheus.ra.internal:9090` | Ad-hoc PromQL queries; check scrape targets; view raw metrics |
| Grafana k6 Cloud | k6 | **0.54.x** | CLI + Cloud | Run load tests; `k6 run est-load-test.js` from developer machine |
| Micrometer Test | `SimpleMeterRegistry` | **1.16.x** | Test scope | In-test metrics assertion: verify `ra.cert.requests.total` increments |
| Spring Boot Actuator | Actuator endpoints | **4.0.3** | `https://ra:8443/actuator` | `curl /actuator/metrics/ra.cert.requests.total` — direct metric lookup |
| Alertmanager UI | Alertmanager | **0.27.x** | `https://alertmanager.ra.internal:9093` | View active alerts, silence noisy alerts during maintenance |

---

### 19C. KAFKA & MESSAGING CLIENT TOOLS

| Tool | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Kafka UI | Provectus Kafka UI | **0.7.2** | Web UI: browse `ra.audit.events`, `ra.cert.issued` Kafka topics; inspect messages |
| kcat (kafkacat) | kcat | **1.7.0** | CLI producer/consumer: `kcat -C -t ra.audit.events -b kafka:9092` |
| Kafka CLI tools | `kafka-console-consumer.sh` | **3.8.0** | Built-in CLI for topic inspection in dev/staging environments |
| Redpanda Console | Redpanda Console | **2.7.x** | Alternative Kafka UI; topic browser, consumer group lag monitoring |
| Spring Kafka Test | `EmbeddedKafkaBroker` | **3.3.x** | In-test embedded Kafka; no Docker needed for unit test Kafka producer/consumer |
| Offset Explorer | Offset Explorer | **3.x** | Desktop GUI | Windows/Mac desktop Kafka browser; useful for ops team |

---

### 19D. HSM & CRYPTOGRAPHY CLIENT TOOLS

| Tool | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Utimaco CryptoServer GUI | Utimaco Security Server Admin | **v5.x** | GUI admin tool for HSM slot management, key inventory, PIN change |
| p11tool | GnuTLS p11tool | **3.8.x** | CLI: enumerate PKCS#11 slots, list keys, test HSM connectivity |
| pkcs11-tool | OpenSC pkcs11-tool | **0.25.x** | CLI: `pkcs11-tool --list-keys --module /usr/lib/libcs_pkcs11_R2.so` |
| SoftHSM2 | SoftHSM2 | **2.6.1** | Software HSM for local dev; PKCS#11 compatible; no hardware needed |
| OpenSSL + PKCS#11 | OpenSSL + engine_pkcs11 | **3.3.x** | Test HSM signing: `openssl req -engine pkcs11 -key slot:0-id:1` |
| keytool | JDK keytool | **JDK 21** | View PKCS#11 keystore: `keytool -list -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11` |
| BC PKIX CLI | Bouncy Castle utilities (test scope) | **1.78.1** | Generate test CSRs, inspect X.509 cert fields, verify chains in developer scripts |

---

### 19E. SECRETS & VAULT CLIENT TOOLS

| Tool | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Vault CLI | HashiCorp Vault CLI | **1.17.6** | `vault kv get secret/ra/hsm-pin` — developer secrets access |
| Vault Web UI | Vault UI | **1.17.6** | Browser-based secrets explorer: `https://vault.ra.internal:8200/ui` |
| Spring Vault | `spring-vault-core` | **3.1.2** | Application-level Vault integration; `@VaultPropertySource` |
| Terraform Vault Provider | Terraform + Vault Provider | **4.4.x** | Infrastructure-as-code secret policy provisioning |
| External Secrets Operator | ESO | **0.10.x** | K8s operator: sync Vault secrets → K8s Secrets automatically |

---

### 19F. REST & API CLIENT TOOLS

| Tool | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| Postman | Postman | **11.x** | Test EST (`/simpleenroll`), OCSP, RA REST API manually; import OpenAPI spec |
| Insomnia | Insomnia | **10.x** | REST client; mTLS client cert configuration for EST endpoint testing |
| cURL | cURL | **8.10.x** | CLI: `curl --cert client.pem --key client.key https://ra/est/simpleenroll` |
| HTTPie | HTTPie | **3.2.x** | Developer-friendly CLI: `http POST https://ra/api/v1/requests profile=TLS_SERVER` |
| Swagger UI | SpringDoc OpenAPI (embedded) | **2.6.0** | `https://ra:8443/swagger-ui.html` — built-in API docs and test UI |
| Redoc | Redoc UI | **2.3.x** | Clean OpenAPI docs rendering; embed in internal developer portal |
| OpenSSL s_client | OpenSSL | **3.3.x** | `openssl s_client -connect ra:8443 -cert client.pem` — mTLS connection test |
| est-client | libest / estclient | **3.2.0** | Reference EST client (Cisco); test `simpleenroll`, `cacerts` RFC 7030 compliance |

---

### 19G. CONTAINER & KUBERNETES CLIENT TOOLS

| Tool | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| kubectl | Kubernetes CLI | **1.31.x** | Manage RA pods, services, config maps, secrets in K8s cluster |
| Helm CLI | Helm | **3.16.x** | `helm upgrade ra-system ./charts/ra` — deploy RA system updates |
| k9s | k9s | **0.32.x** | Terminal UI for Kubernetes; browse pods, logs, exec into RA containers |
| Lens | Lens Desktop | **6.x** | GUI Kubernetes IDE; cluster management, log streaming, metrics view |
| Docker Desktop | Docker Desktop | **4.34.x** | Local container development; run `docker compose up` for dev stack |
| Lazydocker | lazydocker | **0.23.x** | Terminal UI for Docker: view RA containers, logs, stats |
| Trivy CLI | Trivy | **0.56.2** | `trivy image harbor.internal/pki/ra-core:1.0.0` — manual CVE scan |
| Harbor Web UI | Harbor | **2.11.1** | `https://harbor.ra.internal` — view images, scan results, image signing status |

---

### 19H. IDE & DEVELOPER TOOLS

| Tool | Technology | Version (Latest) | Purpose |
|---|---|---|---|
| IntelliJ IDEA | IntelliJ IDEA Ultimate | **2025.3** | Primary IDE for RA Java development; Spring Boot, Kubernetes, database plugins |
| VS Code | Visual Studio Code | **1.95.x** | AsciiDoc authoring, YAML editing, Docker Compose, React frontend |
| Spring Boot DevTools | `spring-boot-devtools` | **4.0.3** | Hot reload in dev mode; auto-restart on class change |
| Spring Boot CLI | Spring Boot CLI | **4.0.3** | `spring init` — scaffold new RA module via CLI |
| start.spring.io | Spring Initializr | Web | Generate new RA sub-module skeleton with Spring Boot 4.0.3 dependencies |
| jEnv / SDKMAN | jEnv / SDKMAN | Latest | Manage multiple JDK versions (JDK 21 for RA, JDK 17 for legacy modules) |
| Gradle Wrapper | `gradlew` / `gradlew.bat` | **9.4.0** | `./gradlew build` — reproducible builds; no system Gradle install required |
| Gradle Init Script | `init.d/` scripts | **9.4.0** | Enterprise proxy, custom repos, organisation-wide build conventions |

---

## COMPLETE DEPENDENCY VERSION MANIFEST (build.gradle.kts)

```kotlin
// ============================================================
// build.gradle.kts — RA System Root Project
// Spring Boot 4.0.3 | Spring Framework 7.0.6 | Gradle 9.4.0
// Upgrade path: 3.3.x → 3.5.x → 4.0.x (do NOT skip 3.5)
// ============================================================

plugins {
    id("org.springframework.boot")        version "4.0.3"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.asciidoctor.jvm.convert")     version "4.0.3"   // Docs: HTML5
    id("org.asciidoctor.jvm.pdf")         version "4.0.3"   // Docs: PDF
    id("org.springdoc.openapi-gradle-plugin") version "2.6.0"
    id("com.github.spotbugs")             version "6.x"
    id("org.owasp.dependencycheck")       version "10.0.4"
    id("jacoco")
    java
}

// ===== VERSION CATALOGUE (libs.versions.toml or inline) =====
val versions = mapOf(
    // ----- Runtime -----
    "java"                  to "21",
    "springBoot"            to "4.0.3",          // Feb 19, 2026
    "springFramework"       to "7.0.6",           // Mar 13, 2026
    "springSecurity"        to "7.0.x",           // SB 4.0 aligned
    "springStateMachine"    to "3.2.1",
    "springCloud"           to "2025.0.x",         // SB 4.0 BOM
    "springVault"           to "3.1.2",
    "springLdap"            to "3.2.4",
    "springKafka"           to "3.3.x",           // SB 4.0 aligned
    "springBatch"           to "5.2.x",           // SB 4.0 aligned

    // ----- Cryptography -----
    "bcFips"                to "2.0.0",
    "bcpkixFips"            to "2.0.4",
    "bcprov"                to "1.78.1",

    // ----- Database -----
    "postgresql"            to "42.7.4",
    "hikariCP"              to "5.1.0",
    "flyway"                to "10.18.0",
    "hibernate"             to "6.5.3.Final",

    // ----- Messaging -----
    "kafka"                 to "3.8.0",
    "avro"                  to "1.11.3",

    // ----- Caching -----
    "lettuce"               to "6.3.2.RELEASE",
    "caffeine"              to "3.1.8",

    // ----- Resilience -----
    "resilience4j"          to "2.2.0",

    // ----- Observability (Section 17) -----
    "micrometer"            to "1.16.x",          // SB 4.0 aligned
    "micrometerTracing"     to "1.6.x",
    "opentelemetry"         to "1.60.1",           // Mar 2026
    "logstashEncoder"       to "7.4",
    "loki4j"                to "1.5.2",

    // ----- Immutable Logs (Section 18) -----
    "immudb4j"              to "1.0.1",

    // ----- Testing (Sections 14 & 15) -----
    "springBootTest"        to "4.0.3",
    "springSecurityTest"    to "7.0.x",
    "junit6"                to "6.0.3",            // Feb 15, 2026 — current gen
    "junit5"                to "5.13.4",            // JUnit 5.x LTS fallback
    "mockito"               to "5.23.0",            // Mar 11, 2026
    "assertj"               to "3.27.7",            // Jan 2026 — CVE patched
    "testcontainers"        to "1.20.2",
    "wireMock"              to "3.9.1",
    "restAssured"           to "5.5.0",
    "datafaker"             to "2.4.2",
    "instancio"             to "5.3.0",
    "awaitility"            to "4.2.2",
    "jmh"                   to "1.37",
    "jacoco"                to "0.8.12",
    "pitest"                to "1.17.1",
    "spotBugs"              to "4.8.6",
    "owaspDepCheck"         to "10.0.4",

    // ----- Documentation (Section 16) -----
    "asciidoctorGradle"     to "4.0.3",
    "asciidoctorj"          to "3.0.0",
    "asciidoctorjPdf"       to "2.3.19",
    "asciidoctorjDiagram"   to "2.3.1",
    "springRestDocs"        to "4.0.0",
    "springdocOpenapi"      to "2.6.0"
)
```

---

## Section 20 — Resiliency Tech Stack (Spring Boot 4.0 Compatible)

> **Purpose:** Fault-tolerance patterns — Circuit Breaker, Rate Limiter, Retry, Bulkhead, Time Limiter — applied to RA's CA backend calls (EJBCA/CMP), HSM operations, OCSP responder, and external IdP (Keycloak). All libraries integrate with Micrometer metrics and Spring Boot Actuator.

### 20A — Core Resiliency Framework

| Component | Technology | Version *(Mar 2026)* | Gradle Artifact | Purpose |
|-----------|-----------|----------------------|-----------------|---------|
| Fault-Tolerance Core | **Resilience4j** | **2.2.0** | `implementation("io.github.resilience4j:resilience4j-spring-boot3:2.2.0")` | Circuit Breaker, Retry, Rate Limiter, Bulkhead, Time Limiter — Spring Boot 3/4 starter |
| Reactive Support | Resilience4j Reactor | **2.2.0** | `implementation("io.github.resilience4j:resilience4j-reactor:2.2.0")` | Project Reactor (`Mono`/`Flux`) operators wrapping Resilience4j decorators |
| AOP / Annotations | Resilience4j AOP | **2.2.0** | `implementation("io.github.resilience4j:resilience4j-spring:2.2.0")` | `@CircuitBreaker`, `@Retry`, `@RateLimiter`, `@Bulkhead`, `@TimeLimiter` annotations |
| Metrics Bridge | Resilience4j Micrometer | **2.2.0** | `implementation("io.github.resilience4j:resilience4j-micrometer:2.2.0")` | Exports CB state, retry count, rate-limiter permits to Micrometer → Prometheus |
| Retry (Spring Core) | **Spring Retry** | **2.0.10** | `implementation("org.springframework.retry:spring-retry:2.0.10")` | `@Retryable` / `@Recover` for Spring-managed beans; Exponential backoff |
| Timeout / Cancel | Project Reactor | **3.7.4** | (transitive via Spring WebFlux) | `.timeout(Duration)` operators; non-blocking time-limiting |
| Health Indicators | Spring Boot Actuator | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-actuator")` | Exposes `/actuator/health` with CB state; `/actuator/circuitbreakers` |

---

### 20B — Resilience4j Pattern Reference

| Pattern | Annotation | Config Property Prefix | RA Usage Scenario |
|---------|-----------|------------------------|-------------------|
| **Circuit Breaker** | `@CircuitBreaker(name="ejbca")` | `resilience4j.circuitbreaker.instances.ejbca.*` | EJBCA CMP endpoint — open after 5 failures in 10s sliding window |
| **Retry** | `@Retry(name="ocsp", fallbackMethod="cachedOcsp")` | `resilience4j.retry.instances.ocsp.*` | OCSP responder — 3 retries, 200ms exponential backoff, retry on `SocketTimeoutException` |
| **Rate Limiter** | `@RateLimiter(name="estEnroll")` | `resilience4j.ratelimiter.instances.estEnroll.*` | EST `/simpleenroll` — 100 req/s per RA node; burst protection |
| **Bulkhead** | `@Bulkhead(name="hsm", type=SEMAPHORE)` | `resilience4j.bulkhead.instances.hsm.*` | HSM signing calls — max 20 concurrent; protects Utimaco slot pool |
| **Thread-Pool Bulkhead** | `@Bulkhead(name="ldapSync", type=THREADPOOL)` | `resilience4j.thread-pool-bulkhead.instances.ldapSync.*` | LDAP sync tasks — dedicated pool; isolates from request-handling threads |
| **Time Limiter** | `@TimeLimiter(name="caRevoke")` | `resilience4j.timelimiter.instances.caRevoke.*` | CA revocation call — 3s hard timeout; prevents hung threads |

---

### 20C — Resiliency Configuration (`application.yml` snippet)

```yaml
resilience4j:
  circuitbreaker:
    instances:
      ejbca:
        registerHealthIndicator: true
        slidingWindowType: COUNT_BASED
        slidingWindowSize: 10
        failureRateThreshold: 50          # Open after 50% failures
        waitDurationInOpenState: 30s
        permittedNumberOfCallsInHalfOpenState: 3
        automaticTransitionFromOpenToHalfOpenEnabled: true
        recordExceptions:
          - java.io.IOException
          - java.util.concurrent.TimeoutException
  retry:
    instances:
      ocsp:
        maxAttempts: 3
        waitDuration: 200ms
        enableExponentialBackoff: true
        exponentialBackoffMultiplier: 2
        retryExceptions:
          - java.net.SocketTimeoutException
  ratelimiter:
    instances:
      estEnroll:
        limitForPeriod: 100
        limitRefreshPeriod: 1s
        timeoutDuration: 0s               # Fail-fast; do not queue
  bulkhead:
    instances:
      hsm:
        maxConcurrentCalls: 20
        maxWaitDuration: 500ms
  timelimiter:
    instances:
      caRevoke:
        timeoutDuration: 3s
        cancelRunningFuture: true
```

---

### 20D — Resiliency Gradle Dependencies (`build.gradle.kts`)

```kotlin
// Resiliency — Section 20
val resilience4jVersion = "2.2.0"

implementation("io.github.resilience4j:resilience4j-spring-boot3:$resilience4jVersion")
implementation("io.github.resilience4j:resilience4j-reactor:$resilience4jVersion")
implementation("io.github.resilience4j:resilience4j-micrometer:$resilience4jVersion")
implementation("org.springframework.retry:spring-retry:2.0.10")
implementation("org.springframework.boot:spring-boot-starter-actuator")
implementation("org.springframework.boot:spring-boot-starter-aop")   // Required for @CircuitBreaker AOP proxy

// Test support
testImplementation("io.github.resilience4j:resilience4j-test:$resilience4jVersion")
```

---

### 20E — Resiliency Version Summary

| Library | Version | Spring Boot 4.0 Compatible | Notes |
|---------|---------|---------------------------|-------|
| Resilience4j | **2.2.0** | ✅ | Requires `spring-boot-starter-aop`; Jakarta EE 11 compatible |
| Spring Retry | **2.0.10** | ✅ | Simpler `@Retryable`; good for Spring bean-level retry |
| Bucket4j (optional) | **8.10.1** | ✅ | Redis-backed distributed rate limiting; supplement to Resilience4j RateLimiter |
| Micrometer (metrics) | **1.16.x** | ✅ | Auto-registered by `resilience4j-micrometer`; CB state exposed as gauge |
| Spring Boot Actuator | **4.0.3** | ✅ | `/actuator/health/circuitBreakers` — live CB state in health endpoint |

---

## Section 21 — DBCP (Database Connection Pool) Tech Stack

> **Purpose:** Connection pool layer between RA application and PostgreSQL 16.4. Covers HikariCP (primary), JDBC driver, pool monitoring, and tuning parameters for RA's write-heavy (certificate issuance) + read-heavy (OCSP/status) workloads.

### 21A — Core DBCP Components

| Component | Technology | Version *(Mar 2026)* | Gradle Artifact | Purpose |
|-----------|-----------|----------------------|-----------------|---------|
| Connection Pool | **HikariCP** | **5.1.0** | `implementation("com.zaxxer:HikariCP:5.1.0")` | Primary DBCP; default in Spring Boot; lowest latency JDBC pool |
| JDBC Driver | **PostgreSQL JDBC** | **42.7.4** | `runtimeOnly("org.postgresql:postgresql:42.7.4")` | Type-4 JDBC driver for PostgreSQL 16.x; supports SSL, SCRAM-SHA-256 |
| R2DBC Pool | **r2dbc-pool** | **1.0.2** | `implementation("io.r2dbc:r2dbc-pool:1.0.2")` | Reactive (non-blocking) connection pool for R2DBC; used in reactive RA modules |
| R2DBC Driver | **r2dbc-postgresql** | **1.0.7** | `implementation("org.postgresql:r2dbc-postgresql:1.0.7")` | R2DBC driver for PostgreSQL; paired with r2dbc-pool |
| Spring Data JDBC | Spring Boot Starter JDBC | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-jdbc")` | Auto-configures HikariCP `DataSource`; `JdbcTemplate`, `NamedParameterJdbcTemplate` |
| JPA / Hibernate | Spring Boot Starter Data JPA | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-data-jpa")` | Hibernate 6.5.x ORM; uses HikariCP pool underneath |
| Connection Pool Metrics | HikariCP + Micrometer | **5.1.0 / 1.16.x** | Auto-registered via `micrometer-core` on classpath | Exposes `hikaricp.*` metrics to Prometheus (pool size, pending threads, timeout rate) |
| Pool Health Check | Spring Boot Actuator | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-actuator")` | `/actuator/health/db` — DataSource ping; `/actuator/metrics/hikaricp.connections` |

---

### 21B — HikariCP Tuning (`application.yml`)

```yaml
spring:
  datasource:
    url: jdbc:postgresql://postgres-primary:5432/ra_db?ssl=true&sslmode=verify-full&sslrootcert=/certs/ca.crt
    username: ${DB_USER}
    password: ${DB_PASS}
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: RA-HikariPool
      # -- Pool sizing (formula: connections = ((core_count * 2) + effective_spindle_count))
      maximum-pool-size: 20            # Max active connections per RA pod
      minimum-idle: 5                  # Idle connections to maintain
      idle-timeout: 600000             # 10 min — reclaim idle connections
      max-lifetime: 1800000            # 30 min — recycle connections (< PostgreSQL idle_in_transaction_session_timeout)
      connection-timeout: 30000        # 30s — throw if no conn available
      keepalive-time: 300000           # 5 min — prevent firewall dropping idle conns (pg_cancel_backend)
      validation-timeout: 5000         # 5s — isValid() check
      leak-detection-threshold: 60000  # 60s — log stack trace if conn not returned
      # -- PostgreSQL optimizations
      connection-init-sql: "SET application_name='pqc-ra'; SET search_path=ra_schema,public"
      data-source-properties:
        prepareThreshold: 5            # Switch to server-side prepared statements after 5 executions
        preparedStatementCacheQueries: 256
        tcpKeepAlive: true
        socketTimeout: 30
        connectTimeout: 10
        reWriteBatchedInserts: true    # Batch INSERT performance for bulk cert issuance
        ssl: true
        sslmode: verify-full
```

---

### 21C — R2DBC Pool Config (Reactive Modules)

```yaml
spring:
  r2dbc:
    url: r2dbc:postgresql://postgres-primary:5432/ra_db
    username: ${DB_USER}
    password: ${DB_PASS}
    pool:
      enabled: true
      initial-size: 5
      max-size: 20
      max-idle-time: 10m
      max-life-time: 30m
      acquire-retry: 3
      max-acquire-time: 30s
      validation-query: "SELECT 1"
```

---

### 21D — DBCP Gradle Dependencies (`build.gradle.kts`)

```kotlin
// DBCP — Section 21
// HikariCP (included via spring-boot-starter-jdbc, explicit for version pinning)
implementation("com.zaxxer:HikariCP:5.1.0")

// JDBC
implementation("org.springframework.boot:spring-boot-starter-jdbc")
implementation("org.springframework.boot:spring-boot-starter-data-jpa")  // includes HikariCP + Hibernate
runtimeOnly("org.postgresql:postgresql:42.7.4")                          // PostgreSQL JDBC driver

// R2DBC (reactive modules only)
implementation("org.springframework.boot:spring-boot-starter-data-r2dbc")
runtimeOnly("org.postgresql:r2dbc-postgresql:1.0.7")
implementation("io.r2dbc:r2dbc-pool:1.0.2")

// Observability (pool metrics auto-registered when on classpath)
implementation("org.springframework.boot:spring-boot-starter-actuator")
implementation("io.micrometer:micrometer-registry-prometheus")           // hikaricp.* metrics → Prometheus

// Test — in-memory PostgreSQL for unit tests
testImplementation("org.testcontainers:postgresql")                      // Real PG in containers
```

---

### 21E — DBCP Version Summary

| Library | Version | Notes |
|---------|---------|-------|
| **HikariCP** | **5.1.0** | Spring Boot 4.0.3 default pool; zero additional config needed for basic setup |
| **PostgreSQL JDBC** | **42.7.4** | Full PostgreSQL 16.x feature support; SCRAM-SHA-256 auth; SSL verify-full |
| **r2dbc-pool** | **1.0.2** | Reactive pool; Spring Boot 4.0 auto-configured via `spring-boot-starter-data-r2dbc` |
| **r2dbc-postgresql** | **1.0.7** | Reactive PostgreSQL driver (R2DBC 1.0 SPI) |
| **Flyway** | **10.18.0** | Schema migration (see Section 5); runs before HikariCP pool warms up |
| **Hibernate** | **6.5.3.Final** | ORM layer sitting above HikariCP; Second-level cache via Caffeine |
| **PgBouncer** *(infra)* | **1.23.1** | Optional sidecar connection pooler at K8s pod level; reduces PG server connections at scale |
| **Micrometer** | **1.16.x** | `hikaricp.connections.active`, `.pending`, `.timeout` auto-exposed |
| **Spring Boot Actuator** | **4.0.3** | `/actuator/health/db` liveness; `/actuator/metrics/hikaricp.connections.active` |

---

### 21F — Connection Pool Monitoring Metrics (HikariCP → Prometheus)

| Metric Name | Type | Description | Alert Threshold |
|-------------|------|-------------|-----------------|
| `hikaricp.connections.active` | Gauge | Currently borrowed connections | > 18 (90% of max=20) → warn |
| `hikaricp.connections.idle` | Gauge | Idle connections in pool | < 2 → warn (pool exhaustion risk) |
| `hikaricp.connections.pending` | Gauge | Threads waiting for connection | > 5 → critical |
| `hikaricp.connections.timeout` | Counter | Total connection timeout events | > 0/min → alert |
| `hikaricp.connections.creation` | Timer | Time to create new connection | p99 > 1s → warn |
| `hikaricp.connections.acquire` | Timer | Time from borrow request to received | p99 > 100ms → warn |
| `hikaricp.connections.usage` | Timer | Connection hold time (borrow → return) | p99 > 5s → warn (leak risk) |
| `hikaricp.connections.max` | Gauge | Configured `maximumPoolSize` | — |
| `hikaricp.connections.min` | Gauge | Configured `minimumIdle` | — |

---

---

## 22. NOTIFICATION SERVICE TECH STACK

> Handles email alerts, SMS, push notifications, and internal system events for certificate lifecycle (issuance, expiry warnings, revocation, approval requests).

### 22A. Core Notification Libraries

| Component | Technology | Version | Gradle Artifact | Purpose / Notes |
|---|---|---|---|---|
| Email (SMTP) | Spring Boot Mail Starter | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-mail:4.0.3")` | SMTP-based email dispatch; wraps Jakarta Mail; TLS/STARTTLS support |
| SMTP Provider | Jakarta Mail (Eclipse Angus) | **2.0.3** | `implementation("org.eclipse.angus:jakarta.mail:2.0.3")` | Jakarta EE 11 mail API; replaces `javax.mail`; pulled transitively by starter |
| Email Templates | Thymeleaf Spring Boot Starter | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-thymeleaf:4.0.3")` | HTML email templates with variable substitution (cert details, expiry dates) |
| Template Alt | Apache FreeMarker | **2.3.33** | `implementation("org.freemarker:freemarker:2.3.33")` | Alternative templating for complex multi-locale email bodies |
| SMS Gateway | Twilio Java SDK | **10.1.3** | `implementation("com.twilio.sdk:twilio:10.1.3")` | SMS OTP, RA approval alerts, cert expiry SMS reminders |
| Push Notification | Firebase Admin SDK (FCM) | **9.4.1** | `implementation("com.google.firebase:firebase-admin:9.4.1")` | Mobile push notifications for RA operator mobile app |
| Async Event Bus | Spring ApplicationEventPublisher | **7.0.6** | Built-in Spring Framework | In-process event dispatch; `@EventListener` + `@Async` for cert lifecycle events |
| Persistent Queue | Apache Kafka 3.8.0 | **3.8.0** | `implementation("org.springframework.kafka:spring-kafka:3.3.x")` | Durable async notification delivery; `notification-events` topic; replay on failure |
| Retry | Spring Retry | **2.0.8** | `implementation("org.springframework.retry:spring-retry:2.0.8")` | Automatic retry on transient SMTP/SMS failures with exponential backoff |

### 22B. Notification Event Types (RA Domain)

| Event | Trigger | Channel | Template |
|---|---|---|---|
| Certificate Issued | Cert status → ISSUED | Email + Kafka | `cert-issued.html` |
| Certificate Expiry Warning | 90 / 30 / 7 days before expiry | Email + SMS | `cert-expiry-warning.html` |
| Certificate Revoked | Revocation request processed | Email | `cert-revoked.html` |
| Approval Required | CSR submitted, pending RA officer | Email + Push | `approval-request.html` |
| Renewal Reminder | Auto-scan nightly batch | Email | `renewal-reminder.html` |
| HSM Key Event | Key generation / destruction | Email + Audit | `hsm-key-event.html` |
| System Alert | Health check failure | Email + PagerDuty | `system-alert.html` |

### 22C. Configuration Reference (`application.yml`)

```yaml
spring:
  mail:
    host: smtp.company.com
    port: 587
    username: ${SMTP_USER}
    password: ${SMTP_PASS}
    properties:
      mail.smtp.auth: true
      mail.smtp.starttls.enable: true
      mail.smtp.ssl.trust: smtp.company.com
  thymeleaf:
    prefix: classpath:/templates/email/
    suffix: .html
    mode: HTML

notification:
  from-address: ra-noreply@company.com
  expiry-warning-days: [90, 30, 7]
  retry:
    max-attempts: 3
    backoff-ms: 2000
```

---

## 23. CI/CD PIPELINE TECH STACK

> Full DevSecOps pipeline from code commit to production deployment on Kubernetes. Security scanning embedded at every stage.

### 23A. Source Control & Triggering

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Source Control | GitHub / GitLab | Latest SaaS | Mono-repo with multi-module Gradle; branch strategy: `main`, `release/*`, `feature/*` |
| CI Engine | GitHub Actions | Latest | Workflow YAML; matrix builds across JDK 21/24; caching of Gradle deps |
| CI Alt | GitLab CI/CD | 17.x | Self-hosted option; `.gitlab-ci.yml` pipelines; integrated container registry |
| Webhook Triggers | GitHub Webhooks | — | Push, PR, tag events trigger pipelines |

### 23B. Build & Test Stage

| Component | Technology | Version | Gradle Artifact / Tool | Purpose / Notes |
|---|---|---|---|---|
| Build Tool | Gradle | **9.4.0** | `./gradlew build` | Kotlin DSL multi-module build; incremental compilation, build cache |
| Compiler | Eclipse Temurin | **21.0.3 LTS** | GitHub Actions `setup-java` | Primary JDK; `--release 21` flag enforced |
| Unit / Integration Tests | JUnit 6.0.3 + Testcontainers 1.20.2 | **6.0.3 / 1.20.2** | `./gradlew test` | Full test suite on every PR; containers for PG, Redis, Kafka |
| Code Coverage | JaCoCo | **0.8.12** | `id("jacoco")` | Minimum 80% line coverage enforced; coverage report to Sonar |
| Code Quality | SonarQube / SonarCloud | **10.6** | `id("org.sonarqube") version "5.1.0"` | SAST, code smells, duplication, branch analysis |
| Bug Detection | SpotBugs | **4.8.6** | `id("com.github.spotbugs") version "6.x"` | Bytecode-level bug detection; FindSecBugs plugin for security checks |
| Style Enforcement | Checkstyle | **10.18.2** | `id("checkstyle")` | Google Java Style enforced; fail build on violation |

### 23C. Security Scanning Stage

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Dependency Vulnerability | OWASP Dependency-Check | **10.0.4** | `id("org.owasp.dependencycheck")`; NVD feed; fail on CVSS ≥ 7.0 |
| Container Image Scan | Trivy | **0.56.2** | Scan Docker image for OS + library CVEs; integrated into GitHub Actions step |
| Secrets Detection | TruffleHog / GitLeaks | **3.82.x / 8.x** | Pre-commit + CI scan; detect API keys, PEM, passwords in commits |
| SAST | Semgrep | **1.x** | Java rules + custom PKI-specific rules; auto PR annotations |
| License Compliance | FOSSA / Gradle License Report | **3.x** | OSS license compatibility check; fail on GPL contamination |
| SBOM Generation | Syft | **1.x** | Generate CycloneDX/SPDX SBOM per release artifact |

### 23D. Artifact & Container Registry

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Container Registry | Harbor | **2.11.1** | Private OCI-compliant registry; Trivy integrated scanning; RBAC |
| Container Build | Docker BuildKit / Buildah | **27.x / 1.37** | Rootless image build; multi-stage Dockerfile; distroless base (`gcr.io/distroless/java21`) |
| Java Artifact Store | Nexus Repository / GitHub Packages | **3.x** | Internal Maven/Gradle artifact hosting; proxy for Maven Central |
| Helm Chart Store | Harbor (OCI) / ChartMuseum | **2.11.1** | Helm 3 OCI chart storage; versioned per release |

### 23E. Deployment & GitOps

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| GitOps CD | ArgoCD | **2.12.x** | Declarative GitOps; auto-sync from `release/*` branch; rollback support |
| Helm | Helm | **3.16.x** | Kubernetes packaging; `values-dev.yaml`, `values-prod.yaml` per environment |
| K8s Cluster | Kubernetes | **1.31** | Target deployment platform; namespace-per-environment |
| Service Mesh | Istio | **1.23.2** | mTLS, traffic shifting, canary deployments, observability sidecar |
| Notifications | ArgoCD Notifications | **1.2.x** | Slack/email on deploy success/failure |

### 23F. Pipeline Flow Summary

```
[Git Push / PR]
    │
    ▼
[GitHub Actions CI]
    ├── 1. ./gradlew build (compile + test)
    ├── 2. ./gradlew jacocoTestReport sonar (quality gate)
    ├── 3. OWASP Dependency-Check (SCA)
    ├── 4. Semgrep SAST scan
    ├── 5. Docker Build (distroless/java21 base)
    ├── 6. Trivy image scan (CVE gate)
    ├── 7. TruffleHog secrets scan
    ├── 8. Syft SBOM generation
    └── 9. Push to Harbor (tag: git-sha + semver)
         │
         ▼
    [ArgoCD GitOps]
         ├── Auto-sync dev namespace
         ├── Manual gate → staging / prod
         └── Helm upgrade with Istio sidecar injection
```

---

## 24. EXTERNALIZED CONFIG & PROFILES TECH STACK

> Manages environment-specific configuration, secrets injection, and Spring profile activation across local / dev / staging / prod.

### 24A. Core Config Stack

| Component | Technology | Version | Gradle Artifact | Purpose / Notes |
|---|---|---|---|---|
| Config Server | Spring Cloud Config Server | **4.2.x** *(2025.0.x BOM)* | `implementation("org.springframework.cloud:spring-cloud-starter-config")` | Centralized config from Git repo; per-profile YAML; encrypted property support |
| Config Client | Spring Cloud Config Client | **4.2.x** | `implementation("org.springframework.cloud:spring-cloud-config-client")` | Auto-fetch config on startup; `/actuator/refresh` for runtime reload |
| Secrets Backend | HashiCorp Vault | **1.17.6** | `implementation("org.springframework.vault:spring-vault-core:3.3.3")` | Dynamic DB credentials, PKI secrets engine, HSM PIN; leases auto-renewed |
| Vault Integration | Spring Cloud Vault | **4.2.x** | `implementation("org.springframework.cloud:spring-cloud-starter-vault-config")` | Bootstrap Vault secrets into `Environment`; AppRole auth method |
| K8s ConfigMap | Spring Cloud Kubernetes | **3.1.x** | `implementation("org.springframework.cloud:spring-cloud-starter-kubernetes-client-config")` | Reads K8s ConfigMaps + Secrets as Spring properties; watch for changes |
| Local Dev Secrets | Spring dotenv | **4.0.0** | `implementation("me.paulschwarz:spring-dotenv:4.0.0")` | Load `.env` file in local dev; never committed to Git |
| Property Encryption | Jasypt Spring Boot | **3.0.5** | `implementation("com.github.ulisesbocchio:jasypt-spring-boot-starter:3.0.5")` | Encrypt sensitive properties in Git config repo (`ENC(...)` prefix) |

### 24B. Spring Profile Strategy

| Profile | Activation | Config Source | Notes |
|---|---|---|---|
| `local` | `SPRING_PROFILES_ACTIVE=local` | `.env` + `application-local.yml` | H2 / Docker Compose; no HSM; self-signed certs |
| `dev` | K8s ConfigMap label | Spring Cloud Config `dev` branch | Real PostgreSQL; software HSM (SoftHSM2); Keycloak dev realm |
| `staging` | K8s ConfigMap label | Spring Cloud Config `staging` branch | Full HSM; Vault dynamic creds; production-like data |
| `prod` | K8s ConfigMap label | Vault + Spring Cloud Config `main` branch | Vault PKI engine; Utimaco HSM; strict TLS; no debug logging |
| `test` | `@ActiveProfiles("test")` in JUnit | `application-test.yml` | Testcontainers; embedded Redis; WireMock for EJBCA |

### 24C. Configuration Hierarchy (Override Order — Lowest to Highest)

```
application.yml (jar classpath)
    ↑
application-{profile}.yml (jar classpath)
    ↑
Spring Cloud Config Server (Git repo)
    ↑
Kubernetes ConfigMap (env-specific)
    ↑
Kubernetes Secret (sensitive keys)
    ↑
HashiCorp Vault (dynamic secrets, HSM PINs)
    ↑
Environment Variables (container overrides)
    ↑
JVM -D flags (emergency overrides)
```

### 24D. Key Properties Reference

| Property Key | Source | Example Value | Notes |
|---|---|---|---|
| `spring.datasource.url` | K8s ConfigMap | `jdbc:postgresql://pg:5432/ra_db` | Per-namespace DNS |
| `spring.datasource.password` | Vault dynamic | `v-role-xxxx-yyy` | Rotated every 24h; auto-renewed |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | Config Server | `https://keycloak/realms/ra` | Per-profile Keycloak realm |
| `ra.hsm.pkcs11.library-path` | Vault / K8s Secret | `/opt/utimaco/libcs2.so` | HSM library path; prod only |
| `ra.hsm.pkcs11.pin` | Vault | `${vault.hsm.pin}` | Dynamic Vault reference |
| `ra.ca.ejbca.url` | Config Server | `https://ejbca:8443/ejbca` | EJBCA CMP endpoint |
| `ra.notification.smtp.password` | Vault | `${vault.smtp.pass}` | Rotated quarterly |

---

---

## 25. SPRING BATCH PROCESSING TECH STACK

> Bulk certificate operations — expiry scans, bulk revocation, CRL generation, renewal campaigns, audit log archival.

### 25A. Core Batch Libraries

| Component | Technology | Version | Gradle Artifact | Purpose / Notes |
|---|---|---|---|---|
| Batch Framework | Spring Batch | **5.2.1** | `implementation("org.springframework.batch:spring-batch-core:5.2.1")` | Chunk-oriented processing; `ItemReader` / `ItemProcessor` / `ItemWriter`; Spring Boot 4.0 compatible |
| Batch Auto-Config | Spring Boot Batch Starter | **4.0.3** | `implementation("org.springframework.boot:spring-boot-starter-batch:4.0.3")` | Auto JobRepository wiring; embedded H2 or PostgreSQL schema |
| Job Scheduler | Quartz Scheduler | **2.5.0** | `implementation("org.springframework.boot:spring-boot-starter-quartz:4.0.3")` | Cron-based job triggers; clustered mode via `QRTZ_*` PostgreSQL tables |
| Scheduler Alt | JobRunr | **7.3.1** | `implementation("org.jobrunr:jobrunr-spring-boot-3-starter:7.3.1")` | Lightweight alternative; dashboard UI; background job with retries |
| Batch Job Store | PostgreSQL 16.4 | **16.4** | Via `spring-batch-core` schema | Job execution metadata; `BATCH_JOB_INSTANCE`, `BATCH_STEP_EXECUTION` tables |
| Batch Metrics | Micrometer | **1.16.x** | `implementation("io.micrometer:micrometer-core:1.16.x")` | `spring.batch.job.*` metrics; step duration, item count, skip count to Prometheus |
| Parallel Steps | Spring Batch Partitioning | **5.2.1** | Built-in `PartitionStep` | Parallel processing of certificate batches by partition key (date range, org) |
| Remote Chunking | Spring Integration | **6.4.x** | `implementation("org.springframework.integration:spring-integration-core:6.4.x")` | Distribute chunk processing across worker pods via Kafka |

### 25B. Batch Job Catalogue (RA Domain)

| Job Name | Schedule | Reader | Processor | Writer | Notes |
|---|---|---|---|---|---|
| `CertExpiryNotificationJob` | Daily 06:00 | DB — certs expiring in 90/30/7d | Build notification payload | Kafka `notification-events` topic | Chunked 500 items |
| `CertRenewalReminderJob` | Weekly Sunday 03:00 | DB — auto-renewal eligible | Validate + generate CSR | EJBCA CMP submit | Idempotent step |
| `CRLGenerationJob` | Every 4 hours | DB — revoked certs | Build CRL structure | EJBCA + CDN upload | `RevocationInfo` list |
| `AuditLogArchivalJob` | Monthly 01st 02:00 | `audit_events` table (> 1 yr) | Compress + hash chain verify | S3 / MinIO archive | Immutability verified before move |
| `OrphanCSRCleanupJob` | Nightly 02:30 | DB — CSRs stuck > 30d | Mark EXPIRED | DB update + audit event | Non-destructive status change |
| `BulkRevocationJob` | On-demand | CSV file or Kafka trigger | Parse + validate serial | EJBCA CMP revoke | Manual trigger via REST API |
| `CertInventoryReportJob` | Monthly 01st 05:00 | Full cert table scan | Aggregate by CA / profile / org | XLSX / PDF report + Email | Uses Apache POI 5.3.0 |

### 25C. Spring Batch Configuration Snippet (`build.gradle.kts`)

```kotlin
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-batch:4.0.3")
    implementation("org.springframework.boot:spring-boot-starter-quartz:4.0.3")
    implementation("org.jobrunr:jobrunr-spring-boot-3-starter:7.3.1")
    implementation("org.springframework.batch:spring-batch-integration:5.2.1")
    testImplementation("org.springframework.batch:spring-batch-test:5.2.1")
}
```

---

## 26. API GATEWAY — DETAILED TECH STACK

> Spring Cloud Gateway sits at the edge of the RA system — routing, rate limiting, auth, circuit breaking, and observability for all inbound protocol traffic (EST, SCEP, CMP, ACME, REST).

### 26A. Core Gateway Stack

| Component | Technology | Version | Gradle Artifact | Purpose / Notes |
|---|---|---|---|---|
| API Gateway | Spring Cloud Gateway | **4.2.x** *(2025.0.x BOM)* | `implementation("org.springframework.cloud:spring-cloud-starter-gateway")` | Reactive `WebFlux`-based gateway; route predicates, filters, TLS termination |
| Rate Limiting | Spring Cloud Gateway + Redis | **4.2.x + Redis 7.4.0** | `implementation("org.springframework.boot:spring-boot-starter-data-redis-reactive")` | `RedisRateLimiter` filter; token bucket per client IP / API key; Lettuce reactive |
| Circuit Breaker | Resilience4j Spring Cloud | **2.2.0** | `implementation("org.springframework.cloud:spring-cloud-starter-circuitbreaker-resilience4j")` | Gateway `CircuitBreaker` filter; fallback response on CA backend unavailability |
| Auth at Gateway | Spring Security OAuth2 Resource Server | **7.0.x** | `implementation("org.springframework.security:spring-security-oauth2-resource-server")` | JWT validation at gateway edge; token introspection optional |
| mTLS Termination | Istio Ingress Gateway | **1.23.2** | Istio sidecar | mTLS client cert auth before traffic reaches Spring Gateway |
| Service Discovery | Spring Cloud Kubernetes | **3.1.x** | `implementation("org.springframework.cloud:spring-cloud-starter-kubernetes-client")` | Discover RA microservice pods via K8s DNS |
| Tracing | Micrometer Tracing + OTLP | **1.16.x + 1.60.1** | `implementation("io.micrometer:micrometer-tracing-bridge-otel")` | Trace-ID propagated through gateway to downstream; exported to Tempo |

### 26B. Gateway Route Configuration Reference

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: est-route
          uri: lb://ra-est-service
          predicates:
            - Path=/.well-known/est/**
          filters:
            - name: CircuitBreaker
              args: { name: estCB, fallbackUri: forward:/fallback/est }
            - name: RequestRateLimiter
              args: { redis-rate-limiter.replenishRate: 50, redis-rate-limiter.burstCapacity: 100 }
            - name: Retry
              args: { retries: 3, statuses: SERVICE_UNAVAILABLE }

        - id: acme-route
          uri: lb://ra-acme-service
          predicates:
            - Path=/acme/**
          filters:
            - name: RequestRateLimiter
              args: { redis-rate-limiter.replenishRate: 100, redis-rate-limiter.burstCapacity: 200 }

        - id: rest-admin-route
          uri: lb://ra-admin-service
          predicates:
            - Path=/api/v1/**
          filters:
            - TokenRelay=
            - name: CircuitBreaker
              args: { name: adminCB, fallbackUri: forward:/fallback/admin }
```

### 26C. Gateway Security Headers Filter

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Clickjacking protection |
| `Content-Security-Policy` | `default-src 'self'` | XSS protection |
| `X-Request-ID` | Generated UUID | Correlation ID injection |
| `Cache-Control` | `no-store` | No caching of cert data |

---

## 27. MULTI-MODULE GRADLE STRUCTURE TECH STACK

> Gradle multi-module project layout for the RA system; promotes separation of concerns, independent builds, and shared convention plugins.

### 27A. Gradle Multi-Module Tools

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Build System | Gradle | **9.4.0** | Multi-project build; `settings.gradle.kts` declares all subprojects |
| DSL | Kotlin DSL | **Gradle 9.4.0 built-in** | `build.gradle.kts` in each module; type-safe, IDE auto-complete |
| Version Catalog | `libs.versions.toml` | **Gradle 9.4.0 built-in** | Centralized dependency versions; `libs.spring.boot.starter.web` aliases |
| Convention Plugins | `buildSrc` / included builds | **Gradle 9.4.0** | Shared build logic extracted into `*.convention.gradle.kts` plugins |
| Dependency Locking | Gradle Dependency Locking | **Gradle 9.4.0 built-in** | `./gradlew dependencies --write-locks`; reproducible dependency resolution |
| Build Cache | Gradle Build Cache | **Gradle 9.4.0 built-in** | Local + remote cache; skip up-to-date tasks; 60-80% faster CI rebuilds |
| Build Scan | Gradle Develocity | **3.19** | `id("com.gradle.develocity") version "3.19"`; performance analytics, test insights |
| Java Platform BOM | Gradle Java Platform | **Gradle 9.4.0 built-in** | `ra-bom` module publishes platform constraints for all submodules |

### 27B. Recommended Module Structure

```
pqc-ra/                                  ← root project
├── settings.gradle.kts                  ← include(":ra-api", ":ra-core", ...)
├── gradle/
│   ├── libs.versions.toml               ← version catalog
│   └── wrapper/gradle-wrapper.properties
├── buildSrc/                            ← convention plugins
│   └── src/main/kotlin/
│       ├── ra.java-conventions.gradle.kts
│       ├── ra.spring-conventions.gradle.kts
│       └── ra.security-conventions.gradle.kts
│
├── ra-bom/                              ← Java Platform BOM module
├── ra-api/                              ← REST + Protocol controllers (EST/SCEP/CMP/ACME)
├── ra-core/                             ← Domain logic, FSM, validation
├── ra-crypto/                           ← BouncyCastle, HSM, PQC operations
├── ra-persistence/                      ← JPA entities, repositories, Flyway
├── ra-notification/                     ← Email, SMS, Kafka notification service
├── ra-batch/                            ← Spring Batch jobs (expiry scan, CRL gen)
├── ra-gateway/                          ← Spring Cloud Gateway module
├── ra-security/                         ← Keycloak, Vault, LDAP, WebAuthn
├── ra-observability/                    ← Micrometer, OpenTelemetry config
├── ra-client/                           ← Generated client SDK (OpenAPI)
└── ra-integration-test/                 ← Cross-module integration tests (Testcontainers)
```

### 27C. `settings.gradle.kts` Reference

```kotlin
rootProject.name = "pqc-ra"

plugins {
    id("com.gradle.develocity") version "3.19"
}

develocity {
    buildScan {
        termsOfUseUrl = "https://gradle.com/terms-of-service"
        termsOfUseAgree = "yes"
    }
}

include(
    ":ra-bom",
    ":ra-api",
    ":ra-core",
    ":ra-crypto",
    ":ra-persistence",
    ":ra-notification",
    ":ra-batch",
    ":ra-gateway",
    ":ra-security",
    ":ra-observability",
    ":ra-client",
    ":ra-integration-test"
)
```

### 27D. `libs.versions.toml` Reference (Version Catalog)

```toml
[versions]
spring-boot            = "4.0.3"
spring-framework       = "7.0.6"
spring-cloud           = "2025.0.x"
bouncy-castle          = "1.78.1"
postgresql             = "42.7.4"
hikari                 = "5.1.0"
flyway                 = "10.18.0"
junit6                 = "6.0.3"
mockito                = "5.23.0"
testcontainers         = "1.20.2"
resilience4j           = "2.2.0"

[libraries]
spring-boot-starter-web      = { module = "org.springframework.boot:spring-boot-starter-web",      version.ref = "spring-boot" }
spring-boot-starter-security = { module = "org.springframework.boot:spring-boot-starter-security", version.ref = "spring-boot" }
bouncy-castle-fips           = { module = "org.bouncycastle:bc-fips",                             version.ref = "bouncy-castle" }
postgresql-driver            = { module = "org.postgresql:postgresql",                             version.ref = "postgresql" }
hikaricp                     = { module = "com.zaxxer:HikariCP",                                   version.ref = "hikari" }
junit-jupiter                = { module = "org.junit.jupiter:junit-jupiter",                       version.ref = "junit6" }

[plugins]
spring-boot              = { id = "org.springframework.boot",        version.ref = "spring-boot" }
spring-dependency-mgmt   = { id = "io.spring.dependency-management", version = "1.1.7" }
asciidoctor              = { id = "org.asciidoctor.jvm.convert",     version = "4.0.3" }
owasp-depcheck           = { id = "org.owasp.dependencycheck",       version = "10.0.4" }
spotbugs                 = { id = "com.github.spotbugs",             version = "6.x" }
```

---

---

## 28. FRONTEND / OPERATOR PORTAL TECH STACK

> Web-based RA Operator Portal for certificate request management, approval workflows, revocation, search, and reporting.

### 28A. Frontend Framework & Build

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| UI Framework | React | **18.3.1** | SPA for RA Operator portal; component-based; hooks-based state management |
| Language | TypeScript | **5.5.x** | Type-safe frontend; strict null checks; interfaces for PKI domain models |
| Build Tool | Vite | **5.4.x** | Fast HMR dev server; Rollup-based prod build; Spring Boot `static/` output |
| UI Component Library | Material UI (MUI) | **5.16.x** | Pre-built components: DataGrid for cert list, Dialogs for approval flow |
| Routing | React Router | **6.28.x** | SPA route management; protected routes with OAuth2 token guard |
| State Management | Zustand | **4.5.x** | Lightweight global state for user session, notification count |
| HTTP Client | Axios | **1.7.x** | REST API calls to RA backend; interceptors for JWT attach + 401 refresh |
| Form Handling | React Hook Form + Zod | **7.53.x + 3.23.x** | CSR submission form, revocation reason form; Zod schema validation |
| Table / Grid | AG Grid Community | **32.x** | High-performance cert inventory grid; server-side pagination + filtering |
| Charts / Metrics | Recharts | **2.13.x** | Dashboard: cert issuance trend, expiry countdown, CA utilization charts |
| Date Handling | date-fns | **3.6.x** | Certificate validity date display, expiry countdown calculation |

### 28B. Frontend Security

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Auth (OIDC/PKCE) | oidc-client-ts | **3.1.x** | PKCE flow with Keycloak; silent token refresh; session management |
| React OIDC Wrapper | react-oidc-context | **3.2.x** | `AuthProvider`, `useAuth()` hook for protected component rendering |
| CSP | Helmet.js (via Spring Security headers) | **7.x** | Content Security Policy headers set at Spring Gateway; no inline scripts |
| CSRF | Spring Security CSRF (Double Submit Cookie) | **7.0.x** | CSRF token injected via `XSRF-TOKEN` cookie; read by Axios interceptor |
| Secure Storage | sessionStorage only | — | Tokens stored in memory / sessionStorage; never localStorage |

### 28C. Server-Side Rendering Option (Thymeleaf)

| Component | Technology | Version | Gradle Artifact | Purpose / Notes |
|---|---|---|---|---|
| Template Engine | Thymeleaf | **3.1.3** | `implementation("org.springframework.boot:spring-boot-starter-thymeleaf:4.0.3")` | Server-rendered fallback for low-JS environments; email templates |
| Security Dialect | Thymeleaf Spring Security | **3.1.2** | `implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6:3.1.2")` | `sec:authorize` role-based UI element hiding |
| Layout Dialect | Thymeleaf Layout Dialect | **3.4.0** | `implementation("nz.net.ultraq.thymeleaf:thymeleaf-layout-dialect:3.4.0")` | Master page layout for admin portal templates |

### 28D. Accessibility & Quality

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Accessibility | axe-core / jest-axe | **4.10.x / 9.0.x** | WCAG 2.1 AA compliance tests in CI |
| Unit Tests | Jest + React Testing Library | **29.7.x / 16.x** | Component unit tests; mock API responses |
| E2E Tests | Playwright | **1.48.x** | Full portal E2E: login → submit CSR → approve → download cert |
| Linting | ESLint + Prettier | **9.x / 3.x** | TypeScript + React rules; enforced in CI |
| Bundle Analysis | rollup-plugin-visualizer | **5.12.x** | Bundle size analysis; ensure < 500 KB gzip |

---

## 29. DISASTER RECOVERY & BACKUP STRATEGY TECH STACK

> Ensures business continuity for the RA system — RPO ≤ 4h, RTO ≤ 2h target across all critical components.

### 29A. Database Backup (PostgreSQL)

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| Continuous WAL Archival | pgBackRest | **2.52** | Continuous WAL archiving to S3/MinIO; point-in-time recovery (PITR); delta restore |
| Logical Backup | `pg_dump` / `pg_dumpall` | **16.4** | Daily logical dumps; per-schema; compressed `.dump` files |
| Streaming Replication | PostgreSQL Streaming Replication | **16.4 built-in** | Hot standby replica in secondary AZ; automatic failover via Patroni |
| HA Cluster Manager | Patroni | **3.3.x** | PostgreSQL HA with etcd; automatic leader election; `pg_promote` on failover |
| Connection Pool DR | PgBouncer | **1.23.x** | Transparent reconnect to new primary after Patroni failover |

### 29B. Kubernetes & Infrastructure Backup

| Component | Technology | Version | Purpose / Notes |
|---|---|---|---|
| K8s Cluster Backup | Velero | **1.14.x** | Backup K8s resources (Deployments, Secrets, ConfigMaps, PVCs); schedule: every 6h |
| Storage Backend | MinIO | **RELEASE.2024-09** | S3-compatible object storage; Velero + pgBackRest target; multi-site replication |
| Helm Release Backup | ArgoCD GitOps | **2.12.x** | All K8s state in Git; cluster rebuild from repo in < 30 min |
| Container Image DR | Harbor Replication | **2.11.1** | Cross-region image replication; no re-pull from internet during DR |
| Secrets DR | Vault DR Replication | **1.17.6** | Vault Enterprise DR replica; promote secondary on primary failure |

### 29C. Cache & Message Queue DR

| Component | Technology | Version | DR Strategy | Notes |
|---|---|---|---|---|
| Redis HA | Redis Sentinel | **7.4.0** | 3-node Sentinel; automatic failover < 30s; `min-slaves-to-write 1` | Session + rate limiter data |
| Redis Persistence | Redis AOF + RDB | **7.4.0** | AOF `everysec` + RDB snapshot every 15 min | Recovery point ≤ 1s for sessions |
| Kafka DR | Kafka MirrorMaker 2 | **3.8.0** | Active-passive cross-DC topic replication; consumer group offset sync | `notification-events`, `cert-events` |
| immudb DR | immudb Replication | **1.9.5** | Follower replica; tamper-evident log replicated in near-real-time | Audit log immutability preserved on replica |

### 29D. RPO / RTO Targets

| Component | RPO Target | RTO Target | DR Method |
|---|---|---|---|
| PostgreSQL (cert data) | ≤ 15 min | ≤ 30 min | Patroni auto-failover + WAL streaming |
| PostgreSQL (full restore) | ≤ 4 h | ≤ 2 h | pgBackRest PITR from S3 |
| Redis sessions | ≤ 1 s | ≤ 30 s | Sentinel auto-failover |
| Kafka topics | ≤ 5 min | ≤ 10 min | MirrorMaker 2 replication |
| K8s cluster | N/A (stateless) | ≤ 30 min | ArgoCD GitOps rebuild |
| immudb audit log | ≤ 1 min | ≤ 15 min | Follower replica promotion |
| Vault secrets | ≤ 0 (sync) | ≤ 5 min | Vault DR replication |
| Container images | N/A | ≤ 10 min | Harbor cross-region replication |

---

## 30. OAuth2 / OIDC DEEP-DIVE TECH STACK

> Complete identity, authentication, and authorization stack for the RA system — operators, automated services, HSM access, and external CA integrations.

### 30A. Core OAuth2 / OIDC Components

| Component | Technology | Version | Gradle Artifact | Purpose / Notes |
|---|---|---|---|---|
| Identity Provider (IdP) | Keycloak | **25.0.6** | Deployed separately (K8s StatefulSet) | RA realm; OIDC / SAML 2.0; LDAP federation; MFA enforcement |
| Resource Server (JWT) | Spring Security OAuth2 Resource Server | **7.0.x** | `implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server:4.0.3")` | JWT validation at API layer; `BearerTokenAuthenticationFilter` |
| OAuth2 Client | Spring Security OAuth2 Client | **7.0.x** | `implementation("org.springframework.boot:spring-boot-starter-oauth2-client:4.0.3")` | PKCE auth-code flow for Operator Portal; token refresh |
| Authorization Server | Spring Authorization Server | **1.4.x** | `implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.4.x")` | Optional custom AS for service-to-service client credentials flow |
| JWT Library | Nimbus JOSE + JWT | **9.48** | `implementation("com.nimbusds:nimbus-jose-jwt:9.48")` | Low-level JWT sign/verify; JWK Set parsing; used internally by Spring Security |
| Token Introspection | RFC 7662 Introspection | Spring Security built-in | `security.oauth2.resourceserver.opaque-token.introspection-uri` | Opaque token validation option (Keycloak introspection endpoint) |
| Device Auth Flow | RFC 8628 Device Flow | Keycloak 25.0.6 | Keycloak config | CLI tool + HSM appliance authentication without browser |

### 30B. Token Strategy

| Token Type | Format | Lifetime | Storage | Usage |
|---|---|---|---|---|
| Access Token | JWT (RS256 / ES256) | 15 min | Memory only (React state) | API calls: `Authorization: Bearer <token>` |
| Refresh Token | Opaque | 8 h | `httpOnly` Secure cookie | Silent refresh via PKCE flow |
| ID Token | JWT (OIDC) | 15 min | Memory only | User info: name, email, roles display |
| Service Token | JWT (Client Credentials) | 1 h | Spring Security context | Service-to-service REST calls |
| mTLS Client Cert | X.509 | 1 year | TLS handshake | HSM + CA backend auth (CMP over HTTPS) |

### 30C. Spring Security Configuration Reference

```kotlin
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/.well-known/est/**", hasRole("EST_CLIENT"))
                authorize("/acme/**", hasRole("ACME_CLIENT"))
                authorize("/api/v1/admin/**", hasRole("RA_ADMIN"))
                authorize("/api/v1/officer/**", hasAnyRole("RA_OFFICER", "RA_ADMIN"))
                authorize("/actuator/health", permitAll)
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                jwt {
                    jwkSetUri = "https://keycloak/realms/ra/protocol/openid-connect/certs"
                    jwtAuthenticationConverter = raJwtAuthenticationConverter()
                }
            }
            sessionManagement { sessionCreationPolicy = STATELESS }
            csrf { disable() }  // stateless JWT; CSRF not applicable
            headers {
                httpStrictTransportSecurity { includeSubDomains = true; maxAgeInSeconds = 31536000 }
                contentSecurityPolicy { policyDirectives = "default-src 'self'" }
                frameOptions { deny() }
            }
        }
        return http.build()
    }
}
```

### 30D. Keycloak Realm Configuration (RA Realm)

| Config Item | Value | Notes |
|---|---|---|
| Realm Name | `ra-realm` | Isolated realm for RA system |
| Client: `ra-portal` | Public, PKCE, `http://portal/callback` | Operator Portal SPA client |
| Client: `ra-backend` | Confidential, Client Credentials | Service-to-service; roles mapped |
| Client: `ra-est-client` | mTLS Client Auth | EST protocol client authentication |
| Password Policy | Min 12 chars, MFA mandatory | Enforced for all operator accounts |
| Identity Federation | Active Directory via LDAP | `spring.ldap.urls=ldap://ad:389` |
| PKCE | `S256` required | All public clients; `code_challenge_method=S256` |
| Access Token Lifetime | 900s (15 min) | Short-lived; `accessTokenLifespan=900` |
| Refresh Token Lifetime | 28800s (8 h) | Session max; revoked on logout |
| Post-Quantum Ready | JWS: ES256 (ECDSA) | Migrate to ML-DSA when Keycloak supports JEP 497 |

### 30E. Scope & Role Matrix

| Role | Scope | Access Level | Assigned To |
|---|---|---|---|
| `RA_ADMIN` | `ra:admin` | Full system access; config, user mgmt, all jobs | PKI administrators |
| `RA_OFFICER` | `ra:officer` | Approve/reject CSRs; revoke certs; search | RA officers |
| `RA_VIEWER` | `ra:read` | Read-only cert search and status | Auditors, support staff |
| `EST_CLIENT` | `ra:est` | EST protocol endpoints only | EST client systems |
| `ACME_CLIENT` | `ra:acme` | ACME protocol endpoints only | DevOps automation |
| `BATCH_SERVICE` | `ra:batch` | Trigger batch jobs; read metrics | Internal scheduler |
| `AUDIT_SERVICE` | `ra:audit` | Write audit events; read immutable log | Internal services |

---

*PKI Architecture Team | Confidential — Internal Use Only | Next Review: 2026-09-14*
