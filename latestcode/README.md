# GraphQL Scanner Agent

**GraphQL Scanner** is a full-featured GraphQL endpoint vulnerability scanner agent. It discovers all queries, mutations, and subscriptions, then systematically tests each one for security flaws across **24 automated checks** and **individual operation testing**.

Give it a GraphQL URL — it runs the full scan and delivers one complete JSON report.

---





## Overview

The scanner executes in **four phases**:

| Phase | What it does |
|-------|-------------|
| **Phase 1 — Setup & Introspection** | Initializes counters, sets ethical headers, discovers the full GraphQL schema |
| **Phase 2 — Generic Security Checks** | Runs 24 automated vulnerability checks against the endpoint |
| **Phase 3 — Individual Testing** | Tests every query and mutation individually with auth bypass, SQLi, NoSQLi, and IDOR probes |
| **Phase 4 — Report** | Generates a complete JSON report with all findings, saves it to file |

---

## 24 Vulnerability Checks

| # | Check | Description |
|---|-------|-------------|
| 1 | Introspection Enabled | Schema is publicly discoverable |
| 2 | Missing Authentication | Protected operations accessible without auth |
| 3 | IDOR / Broken Access Control | Sequential IDs expose other users' data |
| 4 | SQL Injection | String fields vulnerable to SQLi |
| 5 | NoSQL Injection | JSON fields vulnerable to NoSQLi |
| 6 | Query Depth Abuse | Deeply nested queries accepted |
| 7 | Field Suggestion Leak | "Did you mean X?" leaks field names |
| 8 | Debug / Verbose Errors | Stack traces, versions, paths exposed |
| 9 | Batching Abuse | Multiple queries executed in one request |
| 10 | Mutation Abuse | Mutations executable without auth |
| 11 | Alias-based DoS | 100+ aliases accepted |
| 12 | Subscription Abuse | WebSocket subscriptions without auth |
| 13 | SSRF via Input | URL fields allow server-side requests |
| 14 | Information Disclosure | Sensitive fields or data exposed |
| 15 | CORS Misconfiguration | Arbitrary origins allowed |
| 16 | GET-based Query / CSRF | Queries executable via GET |
| 17 | APQ Bypass | Persisted query hash enforcement bypassed |
| 18 | Query Width / Complexity | Expensive fields requested at scale |
| 19 | Response Security Headers | Missing X-Content-Type-Options, HSTS, etc. |
| 20 | Fragment-based Attack | Circular / deep fragment chains bypass depth limits |
| 21 | Directive Overloading | Spam @skip / @include directives |
| 22 | GraphQL Engine Fingerprinting | Apollo, Hasura, Yoga, etc. identified |
| 23 | CDN / WAF Detection | Cloudflare, AWS WAF, Akamai identified |
| 24 | JWT / Token Analysis | Weak JWT algorithms, missing exp claim |

---

## Extended Scanner (45+ Checks)

The **Extended Scanner** adds **21 additional checks** spanning injection, authorization and authentication abuse, information leakage, resource exhaustion, interface exposure, and WebSocket-specific weaknesses:

- **Injection Vulnerabilities:**
  - **SSTI / Server-Side Template Injection** (Check 36)
  - **Command Injection** (Check 35) & **Code Execution** (Check 26)
  - **Log Injection / Log Spoofing** (Check 28)
  - **HTML Injection & Stored XSS** (Checks 27, 29)
  - **Path Traversal** (Check 30)

- **Authorization & Authentication Abuse:**
  - **Mass Assignment** (Check 33) & **Privilege Escalation** (Check 34)
  - **Nested / Field-Level Authorization (BOLA/BFLA)** (Check 41)
  - **JWT Token Forgery (`alg: none`)** (Check 40)
  - **Auth Brute-force via Batch + Alias** (Check 38)
  - **Horizontal / Vertical IDOR Expansion** (Check 32)
  - **HTTP Verb / Content-Type Confusion** (Check 37)

- **Information Leakage & Schema Probing:**
  - **Introspection Bypass Techniques** (Check 44)
  - **`__type` Partial Schema Leak** (Check 39)
  - **Weak Password / Hash Exposure** (Check 31)

- **Resource Exhaustion & DoS:**
  - **Query Cost / Complexity Amplification** (Check 43)
  - **Field Duplication Attack** (Check 25)
  - **N+1 / Resolver Performance DoS** (Check 42)

- **Interface Exposure:**
  - **GraphQL IDE & Voyager Exposure** (Check 45 — GraphiQL, Playground, Voyager)

- **WebSocket & Subscription Weaknesses:**
  - **Cross-Site WebSocket Hijacking (CSWSH)** (Check 46)
  - **WebSocket Subscription Protocol Abuse** (Check 12)


---

## Supplementary Tables

For detailed evaluation results — including skill-file ablation, run-to-run variance, full per-vulnerability detection matrices, and per-model recall — see [Supplementary_Tables.md](Supplementary_Tables.md).

---

## Repository Structure

- **`agent_integration_guide.md`** — Comprehensive guide for AI agent orchestration and setup
- **`Supplementary_Tables.md`** — Evaluation results: ablation, variance, detection matrices, and per-model recall
- **`graphql-scanner/`** — Standard 24-check GraphQL vulnerability scanner skill
- **`extended-graphql-scanner/`** — Extended scanner skill with 45+ automated checks 

---
## Prerequisites
 
Before installing and using this GraphQL Scanner skill, make sure you have the following:
 
- OpenClaw fully installed and configured.

Note: If you haven't installed OpenClaw yet, please refer to the [official OpenClaw documentation](https://docs.openclaw.ai/start/getting-started)  for setup instructions first 

## Installation

You can install either the **standard scanner** (`graphql-scanner`) or the **extended scanner** (`extended-graphql-scanner`) directly by asking your AI agent (referencing the [Agent Integration Guide](agent_integration_guide.md)) or running the installation command.

### Option 1: Ask Your Agent to Install

You can instruct your AI agent directly in chat, pointing it to [agent_integration_guide.md](agent_integration_guide.md):

```text
Please read agent_integration_guide.md and install the graphql-scanner skill into the workspace.
```
*or for the extended version:*
```text
Please read agent_integration_guide.md and install the extended-graphql-scanner skill into the workspace.
```

For full orchestration, safety rules, and invocation patterns, refer to the [Agent Integration Guide](agent_integration_guide.md).

### Option 2: Command for Agent / Terminal

Run the command corresponding to the skill you want to install into your OpenClaw workspace skills directory:

#### Standard Scanner (`graphql-scanner`):
```bash
# Copy skill to OpenClaw workspace skills directory
mkdir -p ~/.openclaw/workspace/skills/graphql-scanner/
cp -r graphql-scanner/* ~/.openclaw/workspace/skills/graphql-scanner/
```

#### Extended Scanner (`extended-graphql-scanner`):
```bash
# Copy extended skill to OpenClaw workspace skills directory
mkdir -p ~/.openclaw/workspace/skills/extended-graphql-scanner/
cp -r extended-graphql-scanner/* ~/.openclaw/workspace/skills/extended-graphql-scanner/
```

---

## Guide for Agent

When configured as a vulnerability scanner agent, follow these instructions to execute scans:

### 1. Launching a Scan
Prompt the agent with the target endpoint URL:

* **Basic scan:**
  ```text
  scan https://api.example.com/graphql
  ```
* **Extended deep scan:**
  ```text
  Run a full vulnerability scan on https://api.example.com/graphql using ultimateqlscan
  ```
* **Authenticated scan (with Bearer token / custom headers):**
  ```text
  scan https://api.example.com/graphql -H "Authorization: Bearer <TOKEN>"
  ```

### 2. Agent Execution Workflow
When a scan command is received, the agent automatically executes all four phases:

1. **Phase 1: Setup & Introspection**
   - Initializes counters (`requests_sent`, `queries_discovered`, `mutations_discovered`).
   - Attaches mandatory research headers (`x-info`, `x-email`, `User-Agent`) to every request.
   - Executes introspection query to extract all queries, mutations, types, and arguments.
   - If introspection is blocked, uses suggestion fuzzing and introspection bypasses to reconstruct schema.
2. **Phase 2: Generic Checks**
   - Runs automated checks (24 checks for standard, 45+ checks for extended).
   - Observes DoS budgets (max 20 aliases, max 10 batch size, recursion depth limits).
3. **Phase 3: Individual Operation Testing (MANDATORY)**
   - Sends real HTTP requests to every discovered query and safe mutation.
   - Tests for auth bypass, SQLi, NoSQLi, and IDOR on each operation.
   - **Skips destructive mutations** (`update`, `delete`, `destroy`, `drop`, `ban`, etc.) to prevent data loss.
4. **Phase 4: Report Generation & Saving**
   - Saves complete JSON report to:
     ```
     {workspace}/graphql_scans/{full_hostname}.json
     ```
   - Verifies the saved file and outputs the final JSON report.

---

## Quick Start

```text
scan https://api.example.com/graphql
```

No confirmation needed. The scanner runs all four phases automatically, saves the report, and returns the complete JSON output.

---


## Payload Safety

The scanner only uses **safe, read-only payloads** — nothing that modifies, deletes, or destroys data.

### SQL Injection — Safe Payloads Only
- `' OR '1'='1` — boolean-based blind detection
- `' UNION SELECT null--` — data structure probing
- `' AND SLEEP(3)--` — time-based detection (max 5 sec)
- `'; SELECT 1--` — simple verification

> **Never:** `DROP`, `DELETE`, `INSERT`, `UPDATE`, or any destructive operation.

### NoSQL Injection — Safe Payloads Only
- `{"$gt": ""}`
- `{"$ne": null}`
- `{"$regex": ".*"}`

---

## Output Format

Every scan produces a complete JSON report with:

- **`scan`** — target URL, timestamp, duration, all discovered operations, engine and CDN/WAF identification
- **`testing_coverage`** — how many queries/mutations were individually tested, names of those tested, names of those skipped and why
- **`key_findings`** — 3–5 most important discoveries in plain language
- **`vulnerabilities`** — every finding with: id, title, category, severity, CVSS estimate, affected operation, plain-language summary, full evidence (request + response + status code), and remediation
- **`summary`** — counts by severity level (critical / high / medium / low / info)

Reports are saved to:
```
/home/openclaw/.openclaw/workspace/graphql_scans/{full_hostname}.json
```

---


## Example JSON Output

```json
{
  "scan": {
    "target": "https://api.example.com/graphql",
    "timestamp": "2026-04-15T10:00:00Z",
    "duration_seconds": 320,
    "requests_sent": 142,
    "schema_discovered": true,
    "graphql_engine": "Apollo Server",
    "cdn_waf": "Cloudflare",
    "queries_discovered": ["user", "product", "order", "search"],
    "mutations_discovered": ["createUser", "updatePassword", "deleteAccount"],
    "total_queries": 4,
    "total_mutations": 3,
    "total_subscriptions": 1,
    "total_types": 28
  },
  "testing_coverage": {
    "total_queries_discovered": 4,
    "queries_tested": 4,
    "queries_tested_names": ["user", "product", "order", "search"],
    "queries_skipped": [],
    "total_mutations_discovered": 3,
    "mutations_tested": 2,
    "mutations_tested_names": ["createUser", "updatePassword"],
    "mutations_skipped": ["deleteAccount"]
  },
  "key_findings": [
    "Authentication bypass: query 'user' returns full user profile without any auth token",
    "IDOR in 'user' query: sequential integer IDs expose all user records",
    "Introspection enabled: full schema including field names and types is publicly accessible"
  ],
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "Broken Access Control — Unauthenticated User Enumeration",
      "category": "2. Missing Authentication",
      "severity": "HIGH",
      "cvss_estimate": 7.5,
      "affected_operation": "user",
      "summary": "The 'user' query accepts an 'id' argument and returns full profile data without requiring authentication.",
      "evidence": {
        "request": "POST /graphql\n{ \"query\": \"{ user(id: 1) { id email name phone } }\" }",
        "response_snippet": "{\"data\":{\"user\":{\"id\":1,\"email\":\"user@example.com\",\"name\":\"John Doe\",\"phone\":\"+1-555-0100\"}}}",
        "status_code": 200
      },
      "remediation": "Add authentication requirements to the 'user' query. Ensure the resolver validates the session or JWT token before returning data."
    }
  ],
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0,
    "info": 1,
    "total": 4
  }
}
```
