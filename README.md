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

## Repository Structure

- **`AGENTS.md`** — Detailed 4-phase workflow and requirements
- **`skills/graphql-scanner`** — Complete scanner skill 

---

## Installation

The scanner is installed as an **OpenClaw agent skill**. Copy the skill folder and register it in your OpenClaw configuration.

### What to copy

Copy the **`skill/`** folder (containing `SKILL.md` and `templates/`) into your OpenClaw skills directory:

```
~/.npm-global/lib/node_modules/openclaw/skills/graphql-scanner/
```

Copy **`AGENTS.md`** into the agent's workspace directory.

## Quick Start

```
scan https://api.example.com/graphql
```

No confirmation needed. The scanner runs all four phases automatically and sends one complete JSON report when done.

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
