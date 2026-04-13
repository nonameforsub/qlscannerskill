# AGENTS.md — GraphQL Scanner Workflow

## CRITICAL: Known Failures in Past Scans

Previous scans have consistently failed on these points. **Fix them NOW:**

1. ❌ `testing_coverage` section was MISSING from ALL 25+ past scans → **MUST be included**
2. ❌ `requests_sent` was MISSING from ALL past scans → **MUST be a real count**
3. ❌ Individual queries/mutations were NEVER actually tested → **Phase 3 is MANDATORY**
4. ❌ `affected_operation` was always generic ("Any query with aliases") → **MUST be specific operation names**
5. ❌ `queries_tested_names` and `mutations_tested_names` were empty/missing → **MUST list actual names**
6. ❌ "Introspection disabled" was reported as INFO finding → **This is NOT a finding. Do NOT include.**
7. ❌ "Introspection enabled" was rated CRITICAL → **It should be MEDIUM (info disclosure, not RCE)**

---

## What is NOT a Finding (NEVER add to vulnerabilities[] or key_findings[])

- **Introspection disabled** — expected secure behavior, not a weakness
- **Authentication required** — correct security control, not a finding
- **Rate limiting active** — good security practice
- **Batching disabled** — expected behavior
- **Query depth limiting active** — expected behavior
- **Subscriptions not available** — not a vulnerability

These are evidence that security controls WORK. Never report them.

---

## Every Scan (Automatic)

When user provides a GraphQL endpoint:

### Step 1: Setup
1. **Initialize counters:** `requests_sent = 0`, `queries_tested_names = []`, `mutations_tested_names = []`, `queries_skipped = []`, `mutations_skipped = []`
2. **Record start time:** `start_time=$(date +%s)`
3. **ALWAYS add these headers to EVERY request:**
   - `x-info: This-is-a-scanner-for-research`
   - `x-email: researchwebconc1-at-gmail-dot-com`
   - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`

### Step 2: Introspection (Phase 1)
3. Send introspection query → `requests_sent += 1`
4. Parse schema → populate `queries_discovered[]` and `mutations_discovered[]`
5. **Extract argument types for each query/mutation** — you need these to construct test requests in Phase 3
6. If introspection is disabled → **NOT a finding**, just set `schema_discovered: false` and continue

### Step 3: Generic Checks (Phase 2 — 24 checks)
7. Execute all 24 checks:
   - **Checks 1-14** (original): introspection, auth, IDOR, SQLi, NoSQLi, depth, suggestions, errors, batching, mutations, aliases, subscriptions, SSRF, info disclosure
   - **Check 7 (Field Suggestion)**: ONLY run if introspection was disabled (schema_discovered: false). If we already have the schema, skip this — it's redundant.
   - **Check 15**: CORS misconfiguration (send request with `Origin: https://evil-attacker.com`, check `Access-Control-Allow-Origin`)
   - **Check 16**: GET-based query support / CSRF (try sending query via GET method)
   - **Check 17**: APQ bypass (test persisted query hash, check if arbitrary queries still work)
   - **Check 18**: Query width/complexity abuse (request ALL fields on complex type)
   - **Check 19**: Response security headers (check for missing `X-Content-Type-Options`, `Strict-Transport-Security`, etc.)
   - **Check 20**: Fragment-based attack (circular/deep fragment chains to bypass depth limiting)
   - **Check 21**: Directive overloading (spam `@skip`/`@include` directives)
   - **Check 22**: GraphQL engine fingerprinting (identify Apollo, Hasura, Yoga, etc. from response patterns)
   - **Check 23**: CDN/WAF detection (identify Cloudflare, AWS WAF, Akamai from response headers)
   - **Check 24**: JWT/Token analysis (if auth provided, decode JWT header, check for `alg: none`, missing `exp`)
8. **Increment `requests_sent` for EVERY HTTP request**
9. **Severity reminder**: Introspection enabled = **MEDIUM** (not CRITICAL)

### Step 4: Individual Query/Mutation Testing (Phase 3 — MANDATORY, DO NOT SKIP)

⚠️ **THIS IS THE MOST IMPORTANT STEP — PREVIOUS SCANS SKIPPED THIS ENTIRELY** ⚠️

10. **Select queries to test:**
   - Review ALL discovered queries and select EVERY query that could potentially have vulnerabilities
   - There is NO hard cap — test as many as needed. Do NOT limit yourself to 20
   - Use risk priority keywords to identify high-value targets, but also test any query that takes user input, returns sensitive data, or looks interesting:
     - CRITICAL: `admin`, `root`, `superuser`, `owner`
     - HIGH: `user`, `viewer`, `profile`, `account`, `auth`, `login`, `token`, `password`, `payment`, `credit`, `billing`, `id`, `me`, `self`, `current`
     - MEDIUM: `search`, `list`, `fetch`, `get`, `export`, `download`, `order`, `transaction`, `history`, `create`, `update`, `delete`
   - If a query takes arguments (especially ID, String, or input types), it is worth testing
   - If in doubt, test it — thoroughness beats speed

11. **For EACH selected query, send an actual HTTP request:**
   ```bash
   curl -s -X POST "<ENDPOINT>" \
     -H "Content-Type: application/json" \
     -H "x-info: This-is-a-scanner-for-research" \
     -H "x-email: researchwebconc1-at-gmail-dot-com" \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     -d '{"query":"query { <queryName>(<args>) { <fields> } }"}'
   # requests_sent += 1
   # queries_tested_names.append("<queryName>")
   ```
   - Build the query using argument types from introspection
   - Use dummy values: `"1"` for ID, `"test"` for String, `1` for Int, `true` for Boolean
   - Request first few scalar fields from the return type
   - Check: does it return data without auth? Does it leak info? Does it expose other users' data?
   - If it has string args, also send SQLi payload: `' OR '1'='1` → `requests_sent += 1`

12. **Select mutations to test:**
    - Review ALL discovered mutations and select EVERY mutation that could potentially have vulnerabilities
    - There is NO hard cap — test as many as needed. Do NOT limit yourself to 20
    - Use risk priority keywords to identify high-value targets, but also do test any mutation that  takes user input and add data:
      - HIGH: `create`, `add`, `new`, `insert`, `user`, `admin`, `auth`, `upload`, `import`
      - MEDIUM: `enable`, `disable`, `toggle`, `approve`, `reject`, `send`, `notify`
    - If a mutation takes arguments, it is worth testing
    - If in doubt, test it — thoroughness beats speed
    - **TEST ALL if total < 30, otherwise test at least 30%. Always test at least 30.**
    - **SKIP all mutations containing: update, delete, remove, destroy, drop, ban, suspend, cancel, revoke, deactivate, execute, write, edit**
      - Add these to `mutations_skipped` list (DO NOT send HTTP requests)
      - These could modify/delete data if accessible without auth

13. **For EACH selected mutation, send an actual HTTP request:**
    ```bash
    curl -s -X POST "<ENDPOINT>" \
      -H "Content-Type: application/json" \
      -H "x-info: This-is-a-scanner-for-research" \
      -H "x-email: researchwebconc1-at-gmail-dot-com" \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
      -d '{"query":"mutation { <mutationName>(<args>) { <fields> } }"}'
    # requests_sent += 1
    # mutations_tested_names.append("<mutationName>")
    ```
    - Build mutation using argument types from introspection
    - Send WITHOUT auth first (if user provided auth) to test auth bypass
    - Check: does it execute? Does it return detailed errors? Does it accept injection payloads?
    - If it has string args, also send SQLi payload → `requests_sent += 1`

14. Test selected operations for: **authentication, authorization, input validation, error handling**
15. Check for rate limiting (429 responses, `X-RateLimit-*`, `Retry-After` headers)
16. Add 1-2s delays if rate limited

### Step 5: Report
17. **Calculate duration:** `duration_seconds=$(($(date +%s) - start_time))`
18. Generate complete JSON report with ALL required sections (see format below)
19. **VERIFY** the pre-report checklist before saving
20. Save to `/home/openclaw/.openclaw/workspace/graphql_scans/{full_hostname}.json`
    - Use FULL hostname (e.g., `innovationpitch.uefa.com.json`, `api.example.com.json`)
    - Everything before the first `/` after the protocol
21. Send ONE message with the COMPLETE JSON

---

## Complete JSON Output Requirements

```json
{
  "scan": {
    "target": "<full URL>",
    "timestamp": "<ISO-8601>",
    "duration_seconds": <number>,
    "requests_sent": <REAL_COUNT_MUST_BE_GREATER_THAN_ZERO>,
    "schema_discovered": true|false,
    "graphql_engine": "<detected engine name or 'unknown'>",
    "cdn_waf": "<detected CDN/WAF or 'none detected'>",
    "queries_discovered": ["<ALL query names from schema>"],
    "mutations_discovered": ["<ALL mutation names from schema>"],
    "total_queries": <number>,
    "total_mutations": <number>,
    "total_subscriptions": <number>,
    "total_types": <number>
  },
  "testing_coverage": {
    "total_queries_discovered": <number>,
    "queries_tested": <number_MUST_BE_GREATER_THAN_ZERO>,
    "queries_tested_names": ["<ACTUAL query names you sent requests to>"],
    "queries_skipped": ["<query names with update/delete/sensitive operations - NOT tested>"],
    "total_mutations_discovered": <number>,
    "mutations_tested": <number>,
    "mutations_tested_names": ["<ACTUAL mutation names you sent requests to>"],
    "mutations_skipped": ["<mutation names with update/delete/sensitive operations - NOT tested>"],
    "selection_criteria": "<explain how many tested and why — e.g. 'ALL 15 queries tested' or '35 of 80 queries tested (all with args or risk keywords)'"
  },
  "key_findings": [
    "<most important finding 1 in plain language>",
    "<most important finding 2 in plain language>",
    "<finding 3>"
  ],
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "<full title>",
      "category": "<check number/name OR 'Query Testing' OR 'Mutation Testing'>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_estimate": <0.0-10.0>,
      "affected_operation": "<SPECIFIC query or mutation name e.g. 'getUser' — NEVER generic text>",
      "summary": "<what happened and what was found - plain language explanation>",
      "evidence": {
        "request": "<exact curl command or HTTP request including URL, headers, body>",
        "response_snippet": "<first 500 chars of actual response>",
        "status_code": <number>
      },
      "remediation": "<specific how to fix>"
    }
  ],
  "summary": {
    "critical": <count>,
    "high": <count>,
    "medium": <count>,
    "low": <count>,
    "info": <count>,
    "total": <count>
  }
}
```

## JSON Field Rules:

| Field | Rule |
|-------|------|
| `requests_sent` | **MUST** be > 0. Count every curl/HTTP request. |
| `queries_discovered` | Array of ALL query names from introspection |
| `mutations_discovered` | Array of ALL mutation names from introspection |
| `testing_coverage` | **MANDATORY** section — scan is INVALID without it |
| `queries_tested` | Number of queries you actually sent HTTP requests to (> 0) |
| `queries_tested_names` | Array of specific query names tested (non-empty) |
| `queries_skipped` | Array of query names with update/delete/sensitive operations - NOT tested |
| `mutations_tested` | Number of mutations you actually sent HTTP requests to |
| `mutations_tested_names` | Array of specific mutation names tested |
| `mutations_skipped` | Array of mutation names with update/delete/sensitive operations - NOT tested |
| `affected_operation` | SPECIFIC name like `getUser`, `createPost` — NEVER "Any query with aliases" or "__schema" |
| `key_findings` | 3-5 most important discoveries — ONLY actual weaknesses, NOT secure behaviors |
| `evidence` | Real request + real response snippet for EVERY vulnerability |
| `graphql_engine` | Detected engine (Apollo, Hasura, etc.) or "unknown" |
| `cdn_waf` | Detected CDN/WAF (Cloudflare, AWS WAF, etc.) or "none detected" |

---

## Pre-Report Verification Checklist

**STOP and verify ALL items before generating the JSON report:**

### 1. Headers (EVERY request)
- [ ] `x-info: This-is-a-scanner-for-research` included
- [ ] `x-email: researchwebconc1-at-gmail-dot-com` included
- [ ] `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` included

### 2. No False Positives
- [ ] "Introspection disabled" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] "Authentication required" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] "Rate limiting active" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] Introspection enabled severity is MEDIUM (not CRITICAL)

### 3. Phase 3 Completed (Individual Testing)
- [ ] Queries were INDIVIDUALLY tested (not just generic checks)
- [ ] Mutations were INDIVIDUALLY tested (not just generic checks)
- [ ] Each tested operation had an actual HTTP request sent to the endpoint
- [ ] `queries_tested_names` is populated with real query names
- [ ] `mutations_tested_names` is populated with real mutation names

### 4. Selection Logic Applied
- [ ] ALL queries with risk keywords or arguments were tested (no arbitrary cap)
- [ ] ALL mutations with risk keywords or arguments were tested (no arbitrary cap)
- [ ] Any query/mutation that takes user input was tested
- [ ] Selection was thorough — when in doubt, tested it
- [ ] Queries with update/delete/destroy/remove/drop/ban/suspend are added to `queries_skipped` (NOT tested)
- [ ] Mutations with update/delete/destroy/remove/drop/ban/suspend are added to `mutations_skipped` (NOT tested)

### 5. Tracking Accurate
- [ ] `requests_sent` is a real count > 0 (counted every HTTP request)
- [ ] `queries_discovered[]` contains all query names from schema
- [ ] `mutations_discovered[]` contains all mutation names from schema
- [ ] `queries_tested_names[]` lists queries you actually sent requests to
- [ ] `mutations_tested_names[]` lists mutations you actually sent requests to
- [ ] `queries_skipped[]` contains update/delete/sensitive query names (NOT tested)
- [ ] `mutations_skipped[]` contains update/delete/sensitive mutation names (NOT tested)
- [ ] `queries_tested` number EQUALS `len(queries_tested_names)` array
- [ ] `mutations_tested` number EQUALS `len(mutations_tested_names)` array

### 6. JSON Complete
- [ ] `scan` section complete with `requests_sent`, `queries_discovered`, `mutations_discovered`, `graphql_engine`, `cdn_waf`
- [ ] `testing_coverage` section EXISTS with all sub-fields populated
- [ ] `key_findings` array with 3-5 findings (only real weaknesses)
- [ ] `vulnerabilities` array — each with specific `affected_operation`, `evidence`, `remediation`
- [ ] `summary` section with counts by severity

### 7. File Save
- [ ] Saved to: `/home/openclaw/.openclaw/workspace/graphql_scans/{full_hostname}.json`
- [ ] Used FULL hostname (e.g., `api.example.com.json`)

---

## Rate Limiting

- Check for: `X-RateLimit-*`, `Retry-After`, 429 status
- If you get a 429 or rate limit response: **add `sleep 2` or `sleep 3` between requests and continue**
- Do NOT stop or give up when rate limited — slow down and keep going
- If `Retry-After` header is present, sleep for that many seconds then resume
- Progressively increase delay if still rate limited: 2s → 5s → 10s
- Do NOT report rate limiting as a finding — it's expected security behavior

## Time Budget

- **Take ALL the time needed** — thoroughness is more important than speed
- Do NOT rush, do NOT skip operations to save time, do NOT cut corners
- If the scan takes 30+ minutes because there are many operations to test, that's fine
- Quality and completeness matter more than finishing fast
- Don't ask — just scan

## Ethical Headers

Add to EVERY request:
- `x-info: This-is-a-scanner-for-research`
- `x-email: researchwebconc1-at-gmail-dot-com`
- `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`

This identifies requests as legitimate security research and helps with responsible disclosure.
