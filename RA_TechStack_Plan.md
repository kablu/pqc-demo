# Registration Authority (RA) System — Complete Technology Stack Plan
**Version:** 1.0 | **Date:** 2026-03-14 | **Architect:** Senior PKI Architect
**Stack Base:** Java 21 LTS + Spring Framework 6.x + Spring Boot 3.3.x

---

## TABLE OF CONTENTS
1. [Project Context & Assumptions](#1-project-context--assumptions)
2. [Architecture Overview](#2-architecture-overview)
3. [Module-wise Technology Stack](#3-module-wise-technology-stack)
4. [Decision Matrix](#4-decision-matrix)
5. [Final Recommended Stack Summary](#5-final-recommended-stack-summary)
6. [Dependency Version Manifest](#6-dependency-version-manifest)
7. [Security Hardening Checklist](#7-security-hardening-checklist)
8. [Roadmap & Phasing](#8-roadmap--phasing)

---

## 1. PROJECT CONTEXT & ASSUMPTIONS

| Parameter              | Assumption / Value                                  |
|------------------------|-----------------------------------------------------|
| **Scale**              | Medium — 1K–100K certificate requests/day           |
| **Environment**        | On-premises + Hybrid Cloud (K8s on bare-metal/VM)   |
| **Compliance**         | RFC 5280, FIPS 140-2 Level 3, NIST SP 800-57, eIDAS |
| **Certificate Types**  | TLS/SSL, S/MIME, Code Signing, Client Auth, IoT/Device |
| **Integration Points** | CA (EJBCA/internal), LDAP/AD, HSM (Utimaco), OCSP, EST/SCEP/CMP |
| **Team Expertise**     | Java, Spring Boot, REST APIs, Docker/K8s            |
| **HA/DR**              | Active-Active HA, RPO < 15 min, RTO < 30 min        |
| **Lifecycle Mgmt**     | Full — issuance, renewal, revocation, re-keying      |

---

## 2. ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXTERNAL CLIENTS / SUBSCRIBERS               │
│         (Browsers, IoT Devices, Enterprise Apps, Admins)         │
└───────────┬────────────────────────────────────┬────────────────┘
            │ HTTPS/mTLS                          │ SCEP/EST/CMP/ACME
            ▼                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API GATEWAY (Spring Cloud Gateway 4.x)        │
│              Rate Limiting | mTLS Termination | WAF              │
└───────────┬─────────────────────────────────────────────────────┘
            │
┌───────────▼─────────────────────────────────────────────────────┐
│                  RA CORE SERVICES (Spring Boot 3.3.x)            │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │  Enrollment  │ │  Validation  │ │   Operator Portal (MVC)  │ │
│  │   Service    │ │   Service    │ │   + React Frontend        │ │
│  └──────┬───────┘ └──────┬───────┘ └────────────┬─────────────┘ │
│         │                │                       │               │
│  ┌──────▼───────────────▼───────────────────────▼─────────────┐ │
│  │            RA WORKFLOW ENGINE (Spring State Machine 3.x)    │ │
│  │    Request → Validation → Approval → Issuance → Notify      │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
└──────────────────────────────┼──────────────────────────────────-┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    INTEGRATION LAYER                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  CA Connector│  │  HSM (PKCS11)│  │  LDAP/AD Connector     │  │
│  │  (EJBCA CMP) │  │  Utimaco     │  │  Spring LDAP 3.x       │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
            │                   │                    │
┌───────────▼──────┐  ┌─────────▼───────┐  ┌────────▼──────────┐
│  PostgreSQL 16   │  │   Redis 7.2      │  │   immudb 1.9       │
│  (Primary Store) │  │  (Session/Cache) │  │  (Audit Logs)      │
└──────────────────┘  └─────────────────┘  └───────────────────┘
```

---

## 3. MODULE-WISE TECHNOLOGY STACK

### 🔷 A. BACKEND LANGUAGE & RUNTIME

| Component         | Technology                        | Version     | Justification |
|-------------------|-----------------------------------|-------------|---------------|
| JDK               | Eclipse Temurin / Amazon Corretto | **21 LTS**  | Virtual threads (Loom), ZGC, support till 2029 |
| Build Tool        | Apache Maven                      | **3.9.6**   | Enterprise standard, plugin ecosystem |
| Alt Build         | Gradle                            | **8.7**     | DSL-based alternative |
| Runtime Container | Spring Boot                       | **3.3.4**   | Native image, Spring Security 6.x, Jakarta EE 10 |
| Framework Core    | Spring Framework                  | **6.1.x**   | AOT processing, virtual thread support |

```
Java 21 Benefits for PKI/RA:
  ✅ Virtual Threads (Project Loom) → High concurrency for cert requests
  ✅ Pattern Matching + Records     → Clean PKCS#10/X.509 model classes
  ✅ ZGC (low-latency GC)           → Consistent response times under load
  ✅ FIPS provider support improved → SunPKCS11 + BouncyCastle FIPS
```

---

### 🔷 B. CRYPTOGRAPHIC LIBRARIES & HSM INTEGRATION

| Component              | Technology                         | Version         | Notes |
|------------------------|------------------------------------|-----------------|-------|
| Primary Crypto Library | Bouncy Castle FIPS Java API        | **2.0.0**       | FIPS 140-2 validated, Cert #4616 |
| Fallback / Utility     | Bouncy Castle (non-FIPS)           | **1.78.1**      | CMP/EST protocol parsing |
| PKCS#11 Provider       | SunPKCS11 (JDK built-in)           | JDK 21 built-in | HSM bridge |
| HSM Hardware           | Utimaco SecurityServer             | **v5.x**        | PKCS#11 + JCE provider |
| HSM Alt (cloud)        | AWS CloudHSM / Azure Dedicated HSM | Latest          | For hybrid deployments |
| TPM Integration        | tpm2-tools + TSS4J                 | **1.0.1**       | Device attestation |
| TLS Stack              | Spring Security + Netty (TLS 1.3)  | **6.3.x**       | mTLS enforcement |

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bc-fips</artifactId>
    <version>2.0.0</version>
</dependency>
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-fips</artifactId>
    <version>2.0.4</version>
</dependency>
<!-- Post-Quantum (JEP 496 complement) -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
```

**Algorithm Support Matrix:**

| Algorithm           | Key Size  | Use Case    | FIPS Approved   |
|---------------------|-----------|-------------|-----------------|
| RSA                 | 2048/4096 | TLS, S/MIME | ✅ Yes           |
| ECDSA (P-256/P-384) | 256/384   | TLS, Code   | ✅ Yes           |
| Ed25519             | 256       | Modern TLS  | ⚠️ Non-FIPS     |
| ML-KEM-768 (JEP496) | -         | Post-Quantum| ✅ NIST FIPS 203 |
| ML-DSA-65 (JEP 497) | -         | PQ Signing  | ✅ NIST FIPS 204 |
| SHA-256/384/512     | -         | Digest      | ✅ Yes           |
| AES-256-GCM         | 256       | Symmetric   | ✅ Yes           |

---

### 🔷 C. DATABASE & STORAGE

| Layer              | Technology                  | Version     | Purpose |
|--------------------|-----------------------------|-------------|---------|
| Primary RDBMS      | PostgreSQL                  | **16.3**    | Certificate requests, workflows, entities |
| Connection Pool    | HikariCP                    | **5.1.0**   | High-performance JDBC pooling |
| ORM                | Spring Data JPA + Hibernate | **6.5.x**   | Entity management |
| Migration          | Flyway                      | **10.15.x** | Schema versioning |
| Cache / Session    | Redis                       | **7.2.5**   | Rate limiting, session, OCSP cache |
| Redis Client       | Lettuce (Spring Data Redis) | **6.3.x**   | Reactive Redis client |
| Immutable Audit    | immudb                      | **1.9.5**   | Tamper-evident certificate audit trail |
| immudb Java Client | immudb4j                    | **1.0.1**   | Java SDK for immudb |
| Backup             | pgBackRest                  | **2.51**    | PostgreSQL backup + PITR |

---

### 🔷 D. CERTIFICATE ENROLLMENT PROTOCOLS

| Protocol | Library / Framework         | Version   | RFC      | Use Case |
|----------|-----------------------------|-----------|----------|----------|
| **EST**  | Custom Spring MVC + BC PKIX | BC 1.78.1 | RFC 7030 | Modern TLS client enrollment |
| **SCEP** | JSCEP                       | **2.5.1** | RFC 8894 | Legacy / IoT / Network devices |
| **CMP**  | BouncyCastle CMP            | BC 1.78.1 | RFC 4210 | Enterprise CA integration |
| **ACME** | Custom (Spring + BC)        | -         | RFC 8555 | Automated TLS cert lifecycle |
| **CMC**  | BouncyCastle CMC            | BC 1.78.1 | RFC 5272 | Advanced RA-to-CA comms |

---

### 🔷 E. API LAYER & WEB FRAMEWORK

| Component          | Technology                    | Version    | Purpose |
|--------------------|-------------------------------|------------|---------|
| Web Framework      | Spring Boot Web (Tomcat)      | **3.3.4**  | REST API server |
| API Gateway        | Spring Cloud Gateway          | **4.1.4**  | Rate limiting, routing, mTLS |
| REST Docs          | SpringDoc OpenAPI (Swagger)   | **2.6.0**  | API documentation |
| Validation         | Hibernate Validator (Jakarta) | **8.0.1**  | Input validation |
| Serialization      | Jackson Databind              | **2.17.2** | JSON serialization |
| gRPC (internal)    | grpc-spring-boot-starter      | **3.1.0**  | Internal service comms |
| Workflow Engine    | Spring State Machine          | **3.2.1**  | Cert request lifecycle FSM |
| Async Processing   | Spring Async + Virtual Threads| JDK 21     | High-throughput request handling |

**Multi-module project structure:**
```
ra-system/
├── ra-api/           # REST/EST/SCEP/CMP endpoints
├── ra-core/          # Business logic + State Machine
├── ra-crypto/        # HSM, CSR validation, cert building
├── ra-integration/   # EJBCA, LDAP, OCSP connectors
├── ra-persistence/   # JPA entities, repositories
└── ra-operator-ui/   # React 18 frontend
```

---

### 🔷 F. IDENTITY & ACCESS MANAGEMENT (IAM)

| Component          | Technology                | Version    | Purpose |
|--------------------|---------------------------|------------|---------|
| Auth Server        | Keycloak                  | **25.0.x** | OIDC/OAuth2/SAML2 identity provider |
| Spring Security    | Spring Security           | **6.3.x**  | AuthN/AuthZ framework |
| LDAP Integration   | Spring LDAP               | **3.2.x**  | AD/LDAP user lookup |
| FIDO2 / Smart Card | WebAuthn4J + PIV          | **0.28.x** | RA Operator hardware auth |
| Secrets Management | HashiCorp Vault           | **1.17.x** | HSM PIN, DB passwords, API keys |
| Vault Spring Boot  | spring-vault              | **3.1.x**  | Vault integration |
| MFA                | Keycloak built-in TOTP    | Built-in   | Operator 2FA |
| Certificate Auth   | X.509 Client Cert (mTLS)  | TLS 1.3    | Subscriber authentication |

**RBAC Roles:**

| Role         | Key Permissions |
|--------------|-----------------|
| RA_OPERATOR  | Submit + view requests |
| RA_OFFICER   | Approve/reject + view audit logs |
| RA_MANAGER   | Dual-approve, revoke, configure profiles |
| RA_AUDITOR   | Read-only, export compliance reports |
| RA_ADMIN     | System config, user mgmt — NO cert approval |

---

### 🔷 G. REVOCATION & LIFECYCLE SERVICES

| Component          | Technology                      | Version   | RFC      |
|--------------------|---------------------------------|-----------|----------|
| OCSP Responder     | Custom Spring Boot (BC OCSP)    | BC 1.78.1 | RFC 6960 |
| CRL Generation     | BouncyCastle X509v2CRLBuilder   | BC 1.78.1 | RFC 5280 |
| CRL Distribution   | Nginx (static CRL hosting)      | **1.27.x**| -        |
| CT Logging Client  | Google Trillian client          | **1.6.x** | RFC 6962 |
| Cert Expiry Notify | Spring Scheduler + SMTP         | Built-in  | -        |
| OCSP Cache         | Redis (TTL-based)               | **7.2.5** | -        |

---

### 🔷 H. INFRASTRUCTURE & DEPLOYMENT

| Component              | Technology              | Version     | Notes |
|------------------------|-------------------------|-------------|-------|
| Containerization       | Docker                  | **26.x**    | Multi-stage, distroless images |
| Container Orchestration| Kubernetes              | **1.30.x**  | Pod Security Standards: Restricted |
| Helm Charts            | Helm                    | **3.15.x**  | RA deployment packaging |
| Service Mesh           | Istio                   | **1.22.x**  | mTLS STRICT between services |
| Secrets in K8s         | HashiCorp Vault + ESO   | **1.17.x**  | External Secrets Operator |
| Ingress                | Nginx Ingress Controller| **1.10.x**  | TLS termination + WAF |
| WAF                    | ModSecurity (OWASP CRS) | **3.3.x**   | OWASP Top-10 protection |
| HA / Load Balance      | MetalLB + Keepalived    | **0.14.x**  | On-prem HA |
| Image Registry         | Harbor                  | **2.11.x**  | Private registry + scanning |
| Image Scanning         | Trivy                   | **0.52.x**  | CVE scan in CI/CD |
| Config Management      | Ansible                 | **2.17.x**  | Node hardening automation |

---

### 🔷 I. MONITORING, LOGGING & AUDIT

| Component            | Technology               | Version     | Purpose |
|----------------------|--------------------------|-------------|---------|
| Metrics Collection   | Micrometer + Prometheus  | **1.13.x**  | JVM, request, crypto metrics |
| Visualization        | Grafana                  | **11.x**    | Cert issuance KPI dashboards |
| Log Aggregation      | ELK Stack                | **8.14.x**  | Centralized structured logging |
| Log Shipper          | Filebeat                 | **8.14.x**  | Log forwarding to ELK |
| Structured Logging   | Logback + Logstash encoder| **7.4**    | JSON log format |
| SIEM Integration     | Splunk Universal Forwarder| **9.2.x**  | Enterprise SIEM |
| Distributed Tracing  | OpenTelemetry + Tempo    | **1.9.x**   | Request tracing across services |
| Audit Log Signing    | immudb (hash-chained)    | **1.9.5**   | Tamper-evident audit trail |

**Key custom Prometheus metrics:**
```
ra_certificate_requests_total{protocol, status, profile}
ra_certificate_issuance_duration_seconds{profile}
ra_hsm_operations_total{operation, status}
ra_ocsp_requests_total{status}
ra_csr_validation_failures_total{reason}
ra_approval_queue_size
ra_certificate_expiry_days{serial, subject}
ra_revocations_total{reason}
```

---

### 🔷 J. OSS PKI PLATFORM EVALUATION

| Platform    | Language | RA Module | FIPS   | Pros                                      | Cons                               | Verdict |
|-------------|----------|-----------|--------|-------------------------------------------|------------------------------------|---------|
| **EJBCA**   | Java     | ✅ Full   | ✅ Yes | Enterprise-grade, Java native, extensible | License cost (Enterprise edition)  | ⭐ **Top Choice as CA backend** |
| Dogtag/IdM  | Java/C   | ✅ Yes    | ✅ Yes | Red Hat backed, FIPS native               | Complex setup, RHEL lock-in        | 🔶 Good for RHEL environments |
| Smallstep   | Go       | ✅ ACME   | ❌ No  | Modern, ACME native                       | Not Java, limited RA workflow      | ❌ Not aligned |
| Boulder     | Go       | ❌ CA only| ❌ No  | Let's Encrypt proven                      | Not Java, limited enterprise scope | ❌ Not aligned |
| CFSSL       | Go       | ❌ Basic  | ❌ No  | Lightweight                               | Not enterprise-grade               | ❌ Too minimal |
| AWS Priv CA | Managed  | ❌        | ✅ Yes | Zero ops overhead                         | No custom RA workflow, vendor lock | 🔶 Hybrid option |

**Decision:** Use EJBCA as CA backend, build custom RA on Spring Boot 3.3.x.
Integration: `RA → EJBCA via CMP (RFC 4210) over mTLS`

---

## 4. DECISION MATRIX

**Scoring: 1 (Poor) → 5 (Excellent)**

| Module / Technology      | Security (30%) | Scalability (20%) | Team Familiarity (15%) | Integration (15%) | Community (10%) | Cost TCO (10%) | **Weighted Score** |
|--------------------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Java 21 (Temurin)        | 5 | 5 | 5 | 5 | 5 | 5 | **5.00** |
| Spring Boot 3.3.x        | 5 | 5 | 5 | 5 | 5 | 5 | **5.00** |
| Bouncy Castle FIPS 2.0   | 5 | 4 | 4 | 5 | 4 | 5 | **4.60** |
| PostgreSQL 16            | 5 | 5 | 4 | 5 | 5 | 5 | **4.85** |
| Redis 7.2                | 4 | 5 | 4 | 5 | 5 | 5 | **4.65** |
| immudb 1.9 (Audit)       | 5 | 4 | 3 | 4 | 3 | 4 | **4.10** |
| Keycloak 25 (IAM)        | 5 | 4 | 4 | 5 | 5 | 5 | **4.75** |
| HashiCorp Vault 1.17     | 5 | 4 | 3 | 4 | 5 | 3 | **4.20** |
| Utimaco HSM (PKCS#11)    | 5 | 4 | 3 | 4 | 4 | 2 | **3.95** |
| Kubernetes 1.30 + Istio  | 5 | 5 | 4 | 4 | 5 | 4 | **4.65** |
| ELK Stack 8.14           | 4 | 4 | 4 | 5 | 5 | 4 | **4.30** |
| EJBCA (CA Backend)       | 5 | 5 | 4 | 5 | 4 | 3 | **4.55** |
| JSCEP 2.5.1 (SCEP)       | 4 | 4 | 4 | 5 | 3 | 5 | **4.15** |
| Spring State Machine 3.2 | 4 | 4 | 4 | 5 | 4 | 5 | **4.30** |

---

## 5. FINAL RECOMMENDED STACK SUMMARY

| Layer               | Technology + Version                                   |
|---------------------|--------------------------------------------------------|
| Runtime             | Java 21 LTS (Eclipse Temurin)                          |
| Framework           | Spring Boot 3.3.4 + Spring Framework 6.1.x             |
| Build               | Apache Maven 3.9.6                                     |
| Crypto              | Bouncy Castle FIPS 2.0.0 + BC PKIX 2.0.4              |
| HSM                 | Utimaco via SunPKCS11 (JDK 21)                         |
| Post-Quantum        | ML-KEM-768 (JEP 496) + ML-DSA-65 (JEP 497)           |
| Primary DB          | PostgreSQL 16.3 + HikariCP 5.1 + Flyway 10.15          |
| Cache               | Redis 7.2.5 (Lettuce client)                           |
| Audit DB            | immudb 1.9.5 (immutable, hash-chained)                 |
| IAM / Auth          | Keycloak 25 + Spring Security 6.3.x                   |
| LDAP                | Spring LDAP 3.2.x                                      |
| Secrets             | HashiCorp Vault 1.17 + spring-vault 3.1                |
| Protocols           | EST (custom) + SCEP (JSCEP 2.5.1) + CMP (BC) + ACME  |
| CA Backend          | EJBCA Community/Enterprise (CMP integration)           |
| Workflow            | Spring State Machine 3.2.1                             |
| API Docs            | SpringDoc OpenAPI 2.6.0                                |
| Containers          | Docker 26 + distroless base image                      |
| Orchestration       | Kubernetes 1.30 + Istio 1.22 (service mesh)           |
| Helm                | Helm 3.15                                              |
| Monitoring          | Prometheus + Grafana 11 + OpenTelemetry + Tempo        |
| Logging             | ELK 8.14 + Filebeat + structured JSON logs             |
| SIEM                | Splunk 9.2 (Universal Forwarder)                       |
| Image Registry      | Harbor 2.11 + Trivy scanning                           |
| OCSP                | Custom Spring Boot + BC RFC 6960                       |
| CT Logging          | Google Trillian client 1.6                             |
| Frontend (Operator) | React 18 + TypeScript + Vite                          |

---

## 6. DEPENDENCY VERSION MANIFEST

```xml
<!-- pom.xml — Parent BOM -->
<properties>
    <!-- Runtime -->
    <java.version>21</java.version>
    <spring-boot.version>3.3.4</spring-boot.version>
    <spring-framework.version>6.1.12</spring-framework.version>
    <spring-security.version>6.3.3</spring-security.version>
    <spring-statemachine.version>3.2.1</spring-statemachine.version>
    <spring-cloud.version>2023.0.3</spring-cloud.version>
    <spring-vault.version>3.1.2</spring-vault.version>

    <!-- Cryptography -->
    <bc-fips.version>2.0.0</bc-fips.version>
    <bcpkix-fips.version>2.0.4</bcpkix-fips.version>
    <bcprov.version>1.78.1</bcprov.version>

    <!-- Database -->
    <postgresql.version>42.7.3</postgresql.version>
    <hikaricp.version>5.1.0</hikaricp.version>
    <flyway.version>10.15.0</flyway.version>
    <hibernate.version>6.5.2.Final</hibernate.version>
    <immudb4j.version>1.0.1</immudb4j.version>

    <!-- Protocols -->
    <jscep.version>2.5.1</jscep.version>

    <!-- Observability -->
    <micrometer.version>1.13.2</micrometer.version>
    <opentelemetry.version>1.40.0</opentelemetry.version>
    <logstash-encoder.version>7.4</logstash-encoder.version>

    <!-- Testing -->
    <junit.version>5.10.3</junit.version>
    <testcontainers.version>1.20.1</testcontainers.version>
    <mockito.version>5.12.0</mockito.version>
    <wiremock.version>3.9.1</wiremock.version>
</properties>
```

---

## 7. SECURITY HARDENING CHECKLIST

### Application Level
- ✅ TLS 1.3 only — disable TLS 1.0, 1.1, 1.2
- ✅ mTLS enforced for all CA-facing and admin API endpoints
- ✅ All private keys stored in HSM — never in application memory
- ✅ CSR validation: key size, algorithm, SAN policy, CN restrictions
- ✅ Dual approval required for high-assurance certificate profiles
- ✅ Rate limiting: per IP, per subscriber, per profile
- ✅ Audit log signed and stored in immudb (tamper-evident)
- ✅ Secrets via Vault — no plaintext passwords in config files
- ✅ RBAC enforced at method level (`@PreAuthorize`)
- ✅ JWT tokens short-lived (15 min access / 8 hour refresh)
- ✅ HTTP Security Headers (HSTS, CSP, X-Frame-Options)

### Infrastructure Level
- ✅ Distroless Docker images — no shell, no package manager
- ✅ Read-only root filesystem in containers
- ✅ Kubernetes Pod Security Standards: Restricted profile
- ✅ Network Policies: default deny, allowlist-only
- ✅ Istio mTLS: STRICT mode between all services
- ✅ Image signing: Cosign + Notation
- ✅ CVE scanning: Trivy in CI/CD (block on CRITICAL)
- ✅ Secrets encrypted at rest (Vault + K8s etcd encryption)
- ✅ Audit logs shipped to SIEM in real-time
- ✅ HSM network isolated (dedicated VLAN)

---

## 8. ROADMAP & PHASING

| Phase | Timeline   | Key Deliverables |
|-------|------------|------------------|
| **1 — Foundation**          | Months 1–3  | Spring Boot skeleton, PostgreSQL+Flyway, HSM PKCS#11, BC FIPS, Keycloak RBAC, Docker/K8s dev env |
| **2 — Core RA Workflows**   | Months 4–6  | Spring State Machine lifecycle, EJBCA CMP integration, EST+SCEP protocols, Operator UI, immudb audit |
| **3 — Advanced Protocols & HA** | Months 7–9 | CMP+ACME, OCSP responder, CRL/Nginx, Vault, Istio mTLS strict, ELK+Grafana, HA active-active (3 replicas), 100K/day load test |
| **4 — Compliance & PQ**     | Months 10–12| FIPS 140-2 validation, pentest, CT log (Trillian), ML-KEM/ML-DSA (JEP 496/497), DR drill, production go-live |

---

*Document prepared by PKI Architecture Team | Confidential — Internal Use Only*
*Next Review Date: 2026-09-14*
