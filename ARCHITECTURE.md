# VaultGuard DevSecOps: Architecture & Security Engineering Specification

VaultGuard DevSecOps is a high-assurance fintech microservice and security pipeline designed to demonstrate enterprise Application Security, DevSecOps automation, and Cloud-Native Defense-in-Depth.

---

## 1. Purple Team Engineering Lifecycle: The Two-Repository Ecosystem

This project forms the defensive and automation counterpart to our **API Security Audit Engine (`Project-1`)**:

```mermaid
flowchart LR
    subgraph "Project 1: Offensive Audit & Discovery Engine"
        OpenAPI[OpenAPI 3.1 Contract] --> Auditor[Autonomous Compliance Runner]
        Auditor --> ProbeBOLA[Probe BOLA / IDOR]
        Auditor --> ProbeAuth[Probe JWT RFC 7519 Flaws]
        Auditor --> ProbeBFLA[Probe Administrative RBAC]
        Auditor --> Report[Vulnerability Telemetry & Audit Report]
    end

    subgraph "VaultGuard DevSecOps: Defensive Architecture & CI/CD Gate"
        Report --> Remediation[Code Remediation: Scoped Queries & SSRF Guard]
        Remediation --> SemgrepAST[Custom AST Rules: .semgrep/vaultguard-rules.yml]
        Remediation --> HardenedDocker[Multi-Stage Container & Least Privilege]
        SemgrepAST --> CICD[GitHub Actions Automated Security Gate]
        HardenedDocker --> CICD
        Remediation --> DynRegress[Dynamic Authorization & Regression Suite]
        DynRegress --> CICD
    end
```

### Full-Lifecycle Workflow
1. **Discovery (Project-1):** An automated compliance engine parses OpenAPI specifications, launches deterministic role-swapping payloads, and discovers Broken Object Level Authorization (CWE-639), Broken Function Level Authorization (CWE-285), and weak token hygiene.
2. **Defensive Remediation (`vaultguard-devsecops`):** Engineering teams implement AST-level parameterization, tenant-joined ORM constraints, and egress network isolation (`ssrfGuard.ts`).
3. **Continuous Enforcement (`vaultguard-devsecops` CI/CD):** Custom Semgrep rules and Trivy container audits act as static and IaC gates, while dynamic regression tests assert multi-tenant isolation on every Git commit.

---

## 2. Threat Modeling & Security Controls

```mermaid
flowchart TD
    Client[Incoming Client Request] --> Gateway[Express Middleware Chain]
    
    subgraph "Perimeter Defense & Identity Context"
        Gateway --> SecMode[Security Mode Selector: x-security-mode Header / Query / Env]
        SecMode --> JWTVerify[JWT Authentication & RFC 7519 Normalizer]
        JWTVerify --> Context[Populate req.user: sub, userId, tenantId, role]
    end

    subgraph "Data Access Layer (SQLi & BOLA Mitigation)"
        Context --> RouteInv["/api/invoices/:id"]
        RouteInv --> AuthAssert{ownerId === req.user.sub?}
        AuthAssert -->|No| BlockBOLA["403 Forbidden (BOLA_BLOCKED)"]
        AuthAssert -->|Yes| DBFetch["Scoped SQLite Query (ORM AST)"]

        Context --> RouteSearch["/api/invoices/search?client="]
        RouteSearch --> ParamQuery["Scoped ORM Query: ownerId = req.user.sub AND contains(client)"]
    end

    subgraph "Egress Network Guard (SSRF Mitigation)"
        Gateway --> RouteHook["/api/webhooks/verify"]
        RouteHook --> SSRFModule["src/security/ssrfGuard.ts"]
        SSRFModule --> SchemeCheck{Protocol == 'https:'?}
        SchemeCheck -->|No| BlockScheme["400 Protocol Disallowed"]
        SchemeCheck -->|Yes| DNSLookup["dns.promises.lookup (A & AAAA Records)"]
        DNSLookup --> CIDRCheck{Loopback, RFC 1918, or Cloud IMDS?}
        CIDRCheck -->|Match Prohibited Range| BlockIP["400 SSRF Prohibited IP"]
        CIDRCheck -->|Public IP Validated| PinnedFetch["safeOutboundFetch (redirect: 'manual')"]
    end
```

### Threat 1: Multi-Tenant Data Leakage (CWE-639 BOLA / IDOR)
- **Vector:** An authenticated merchant modifies the document identifier in `GET /api/invoices/103` to retrieve an invoice owned by a competing merchant.
- **Control:** The database query eliminates single-attribute lookups (`where: { id }`). The query boundary requires a composite predicate joining primary key with caller identity:
  ```typescript
  await prisma.invoice.findFirst({
    where: { id, ownerId: req.user.sub }
  });
  ```

### Threat 2: SQL Injection & Grammar Mutation (CWE-89)
- **Vector:** An attacker sends `%' OR '1'='1` in the `client` parameter, intending to alter the query AST disjunction to return all invoices.
- **Control:** Replaces raw string concatenation (`$queryRawUnsafe`) with type-safe Prisma ORM queries. Parameters are bound out-of-band to SQLite virtual machine registers, neutralizing SQL syntax mutation.

### Threat 3: Server-Side Request Forgery & Cloud Credential Theft (CWE-918)
- **Vector:** An attacker submits `http://169.254.169.254/latest/meta-data/` to compromise AWS/GCP instance metadata credentials, or `http://127.0.0.1:4000/api/...` to bypass perimeter firewalls.
- **Control:** `src/security/ssrfGuard.ts` enforces:
  1. Scheme pinning (`https:` only).
  2. Complete DNS resolution over all `A` and `AAAA` records.
  3. Bitwise CIDR blocking against `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, and `fe80::/10`.
  4. Manual redirect enforcement (`redirect: 'manual'`) to neutralize TOCTOU DNS rebinding pivots.

---

## 3. Automated DevSecOps Gate Architecture

Our GitHub Actions pipeline executes three automated gates:

```mermaid
flowchart TD
    Commit[Git Push / Pull Request to main] --> Pipeline[GitHub Actions Security Gate]
    
    subgraph "Job 1: Static AST Analysis"
        Pipeline --> SAST[Semgrep AST Scan: .semgrep/vaultguard-rules.yml]
        SAST -->|AST Match without ownerId| FailSAST1[Flag BOLA: CWE-639]
        SAST -->|AST Match with $queryRawUnsafe| FailSAST2[Flag SQLi: CWE-89]
        SAST -->|AST Match with unvalidated fetch| FailSAST3[Flag SSRF: CWE-918]
    end

    subgraph "Job 2: Supply Chain & Container Security"
        Pipeline --> Trivy[Trivy Scanner]
        Trivy -->|Scan package-lock.json| CVECheck[Dependency CVE Audit]
        Trivy -->|Scan Dockerfile| CISCheck[CIS Benchmark & Non-Root Audit]
        CISCheck -->|Dockerfile.vulnerable: root user| FailTrivy[Block Build: DS-0002]
        CISCheck -->|Dockerfile: USER node| PassTrivy[Pass Container Gate]
    end

    subgraph "Job 3: Dynamic Runtime Regression"
        Pipeline --> SetupDB[Prisma Push & Seed SQLite]
        SetupDB --> StartApp[Start Microservice with SECURITY_MODE=secure]
        StartApp --> HealthWait[Wait for Health Check on Port 4000]
        HealthWait --> ExecTests[Run verify-controls.ts Suite]
        ExecTests -->|All 10 BOLA/SQLi/SSRF Controls Pass| PassCICD[Green CI Build]
    end
```

---

## 4. Dual-Mode Architecture & Precedence

The application features a deterministic runtime toggle:
1. **HTTP Request Header:** `x-security-mode: vulnerable | secure` (highest priority).
2. **URL Query Parameter:** `?mode=vulnerable | secure`.
3. **Environment Variable:** `SECURITY_MODE=vulnerable | secure` (fallback).

This allows developers, security auditors, and automated CI pipelines to test both vulnerable behavior (vulnerability reproduction) and patched behavior (compliance verification) within the same deployment.
