---
name: graphql-scanner
description: Professional GraphQL endpoint vulnerability scanner — introspects schema, probes for security weaknesses, tests individual queries/mutations, returns structured JSON report
---

# GraphQL Vulnerability Scanner

When a user provides a GraphQL endpoint URL, execute this full scanning workflow. **Do not skip any phase. Do not skip Phase 3 (Query/Mutation Testing). Every finding must include real evidence.**

## Prerequisites

You need the `exec` tool (for curl) or `http` tool to make HTTP requests to the target endpoint. If neither is available, tell the user you cannot scan without HTTP access.

**TIMEOUT SETTINGS:**
- Set `--max-time 10` on ALL curl commands to prevent individual requests from hanging too long
- Request a longer session timeout from OpenClaw (e.g., 900 seconds / 15 minutes) if needed for large schemas
- The scan can take 10+ minutes when testing many operations — ensure timeout is sufficient

---

## CRITICAL RULES (READ FIRST)

1. **ALWAYS RESCAN — NEVER USE CACHED RESULTS** — Even if OpenClaw shows "Status: ✅ Active — unchanged" or similar, perform a full fresh scan. Do not check for existing scan files or skip scanning because a previous scan exists. Every scan must be complete and fresh.
2. **YOU MUST ACTUALLY TEST INDIVIDUAL QUERIES AND MUTATIONS** — Not just run generic checks. Phase 3 is MANDATORY.
3. **⚠️ NEVER TEST DESTRUCTIVE MUTATIONS ⚠️** — Mutations containing `delete`, `update`, `remove`, `destroy`, `drop`, `ban`, `suspend`, `cancel`, `revoke`, `deactivate` MUST be SKIPPED. Only test safe mutations (create, add, login, verify, enable, disable, publish, send, notify, etc.). Violating this makes the scan INVALID.
4. **EVERY curl/HTTP request you send counts toward `requests_sent`** — Start counting from request #1 and increment for every single request.
5. **The `testing_coverage` section is MANDATORY** in the final JSON — if it's missing, the scan is INCOMPLETE.
6. **Add research headers to EVERY request** — no exceptions.
7. **Each tested query/mutation must appear by name** in `queries_tested_names` or `mutations_tested_names`.
8. **"Introspection disabled" is NOT a finding** — it is expected secure behavior. Do NOT add it to `vulnerabilities` or `key_findings`.
9. **Only report actual weaknesses** — expected/correct security behavior (introspection disabled, auth required, rate limiting active) should NEVER appear as vulnerabilities. At most, mention them briefly in the scan summary text but never in `vulnerabilities[]` or `key_findings[]`.

---

## Phase 1: Schema Discovery

### Tracking (START NOW)

Before sending any request, initialize these counters:
```
requests_sent = 0
queries_discovered = []
mutations_discovered = []
queries_tested_names = []
mutations_tested_names = []
queries_skipped = []
mutations_skipped = []
start_time=$(date +%s)
```

**Increment `requests_sent` by 1 for EVERY curl/HTTP request you send throughout the entire scan.**

At the end of the scan, calculate duration:
```
end_time=$(date +%s)
duration_seconds=$((end_time - start_time))
```

### 1.1 — Introspection Query

**MANDATORY HEADERS ON EVERY REQUEST:**
```bash
-H "Content-Type: application/json" \
-H "x-info: This-is-a-scanner-for-research" \
-H "x-email: researchwebconc1-at-gmail-dot-com" \
-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

**TIMEOUT: Set `--max-time 30` on all curl requests to prevent hanging.**

Send the full introspection query from `skills/graphql-scanner/templates/introspection.graphql` to the endpoint:

```bash
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"<INTROSPECTION_QUERY>"}'
# requests_sent += 1
```

If the user provides authorization headers or tokens, include them in every request.

### 1.2 — Parse Schema

From the introspection response, extract:
- **Queries**: all fields on the `Query` type → store in `queries_discovered`
- **Mutations**: all fields on the `Mutation` type → store in `mutations_discovered`
- **Subscriptions**: all fields on the `Subscription` type (if any)
- **Types**: all object types, input types, enums, scalars
- **Sensitive fields**: fields named `password`, `token`, `secret`, `ssn`, `creditCard`, `apiKey`, or similar
- **Arguments for each query/mutation**: Store the argument names and types — you will need these for Phase 3

### 1.3 — Handle Introspection Failure

If introspection is disabled (error or empty response):
- **This is expected secure behavior — do NOT report it as a vulnerability or key finding**
- Do NOT add "Introspection disabled" to `vulnerabilities[]` or `key_findings[]`
- Attempt field suggestion probing (Phase 2, Check 7) to discover partial schema
- Continue with whatever operations you can discover
- Note in the scan section: `"schema_discovered": false`

---

## Phase 2: Generic Vulnerability Checks (24 checks)

Run each check below. For each, record the **exact request**, **response snippet** (truncated to ~500 chars), **status code**, and your determination. **Increment `requests_sent` for each HTTP request.**

**⚠️ CRITICAL SAFETY RULE FOR ALL PHASE 2 CHECKS:**
**Do NOT test any query or mutation whose name contains `delete` or `update` (or similar destructive keywords like `remove`, `destroy`, `drop`). Skip them entirely.**

### Check 1: Introspection Enabled (MEDIUM)

- **Already tested in Phase 1**
- If full schema returned → **MEDIUM** vulnerability
- In production, introspection should be disabled

### Check 2: Missing Authentication (HIGH)

Send a simple query **without** any auth headers:
```graphql
query { __typename }
```
Then try actual schema queries (first 2-3 Query fields) without auth. If they return data → **HIGH**.

### Check 3: IDOR / Broken Access Control (CRITICAL)

For queries that take `id` arguments (like `user(id: ...)`, `order(id: ...)`):
- Try sequential IDs: `1`, `2`, `3`
- Try UUIDs if the schema suggests them
- If data is returned for IDs that shouldn't belong to the caller → **CRITICAL**

### Check 4: SQL Injection (CRITICAL)

For string-type input arguments, inject standard SQLi payloads:
```
' OR '1'='1
'; SELECT SLEEP(5); --
" OR ""="
1' UNION SELECT null,null,null--
```
Check for: SQL error messages, unexpected data return, different response behavior.

### Check 5: NoSQL Injection (HIGH)

For string inputs, inject NoSQL operators:
```json
{"$gt": ""}
{"$ne": null}
{"$regex": ".*"}
```
Check for: unexpected data return, different response behavior vs normal input.

### Check 6: Query Depth Abuse (MEDIUM)

Send a deeply nested query (10+ levels deep) using self-referential types:
```graphql
query { user { friends { friends { friends { friends { friends { name } } } } } } }
```
If the server processes it without error or timeout → **MEDIUM** (no depth limiting).

### Check 7: Field Suggestion Leak (LOW)

**ONLY run this check if introspection was disabled (schema_discovered: false).**

If introspection is enabled (we already got the full schema), skip this check — it's redundant.

If introspection is disabled, send a query with a slightly misspelled field name:
```graphql
query { usr }
```
If the error response includes "Did you mean 'user'?" → **LOW** (field name disclosure).

### Check 8: Debug / Verbose Errors (MEDIUM)

Send malformed queries and check error responses for:
- Stack traces
- Internal file paths
- Database names or table names
- Framework/library version info

```graphql
query { __nonexistent }
```

### Check 9: Batching Abuse (MEDIUM)

Send a batched request (array of queries):
```json
[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]
```
If all execute successfully → **MEDIUM** (no batching limits, enables brute-force/rate-limit bypass).

### Check 10: Mutation Abuse (HIGH)

For each mutation discovered (SKIP any mutation containing `delete` or `update` keywords):
- Attempt to call it **without authentication** (if auth was provided, try without)
- Try with minimal/empty arguments to see error messages
- If mutations execute without proper auth → **HIGH**

### Check 11: Alias-based DoS (MEDIUM)

Send a query with many aliases of an expensive operation:
```graphql
query {
  a1: expensiveQuery { id }
  a2: expensiveQuery { id }
  a3: expensiveQuery { id }
  ...repeat 50+ times
}
```
If the server processes all aliases → **MEDIUM** (no alias/complexity limiting).

### Check 12: Subscription Abuse (MEDIUM)

If subscriptions exist in the schema, attempt to subscribe without auth:
```json
{"query": "subscription { <first_subscription_field> { id } }"}
```
If accepted → **MEDIUM**.

### Check 13: SSRF via Input (HIGH)

For input fields that accept URL/URI strings:
```graphql
mutation { importData(url: "http://169.254.169.254/latest/meta-data/") { result } }
```
If the server fetches the URL and returns cloud metadata → **HIGH**.

### Check 14: Information Disclosure (MEDIUM)

Scan the schema for sensitive field names:
- `password`, `passwordHash`, `hashedPassword`
- `token`, `accessToken`, `refreshToken`, `apiKey`, `secret`
- `ssn`, `socialSecurity`, `creditCard`, `cvv`
- `internalId`, `debugInfo`, `adminFlag`

If found exposed in query responses → **MEDIUM**.

### Check 15: CORS Misconfiguration (HIGH)

Send a request with an `Origin` header and check the response:
```bash
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil-attacker.com" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"{ __typename }"}'
# requests_sent += 1
```
Check response headers:
- `Access-Control-Allow-Origin: *` → **HIGH** (allows any site to steal authenticated data)
- `Access-Control-Allow-Origin: https://evil-attacker.com` (reflects origin) → **HIGH**
- `Access-Control-Allow-Credentials: true` combined with reflected origin → **CRITICAL**
- Proper restrictive origin → not a finding

### Check 16: GET-based Query Support / CSRF (MEDIUM)

Test if the endpoint accepts queries via GET (enables CSRF attacks):
```bash
curl -s --max-time 30 -G "<ENDPOINT>" \
  --data-urlencode 'query={ __typename }' \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
# requests_sent += 1
```
If it returns valid data via GET → **MEDIUM** (queries can be triggered via `<img>` tags, links, CSRF).
If mutations also work via GET → **HIGH**.

### Check 17: Automatic Persisted Queries (APQ) Bypass (LOW)

Test if APQ is enabled:
```bash
# Step 1: Try APQ with a hash
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}'
# requests_sent += 1
```
If APQ is enabled but arbitrary (non-persisted) queries still work alongside → **LOW** (APQ provides no security benefit).

### Check 18: Query Width / Complexity Abuse (MEDIUM)

Send a query requesting ALL fields on a type (width attack):
```graphql
query { <queryName> { field1 field2 field3 ... all_fields } }
```
Pick a query that returns a complex type with many fields. Request all fields plus nested objects.
If the server processes it without cost limiting → **MEDIUM** (no query complexity/cost analysis).

### Check 19: Response Security Headers (LOW)

Check response headers from any previous request for:
- Missing `Content-Type: application/json` (could enable sniffing)
- Missing `X-Content-Type-Options: nosniff`
- Missing `Strict-Transport-Security` (if HTTPS endpoint)
- Missing `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`
- `Server` header leaking version info (e.g., `Server: nginx/1.18.0`)

Report each missing security header as **LOW**. Group them in one vulnerability.

### Check 20: Fragment-based Attack (MEDIUM)

Send a query with circular/excessive fragment usage to bypass depth limiting:
```graphql
query {
  ...A
}
fragment A on Query {
  <queryName> {
    ...B
  }
}
fragment B on <ReturnType> {
  <field> {
    ...C
  }
}
fragment C on <NestedType> {
  <field> {
    id
  }
}
```
If the server processes deeply chained fragments without limits → **MEDIUM** (fragment-based depth bypass).

### Check 21: Directive Overloading (MEDIUM)

Send a query spamming `@skip`/`@include` directives:
```graphql
query {
  <queryName> @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) {
    id
  }
}
```
If the server processes 10+ duplicate directives per field without error → **MEDIUM** (no directive limit).

### Check 22: GraphQL Engine Fingerprinting (INFO)

Analyze responses from previous checks to identify the GraphQL engine:
- **Apollo Server**: Look for `"extensions":{"cacheControl":...}`, error format with `"extensions":{"code":"..."}`
- **Hasura**: Look for `x-hasura-*` headers, `"errors":[{"extensions":{"path":"...","code":"..."}}]`
- **graphql-yoga / Yoga**: Look for `Server: GraphQL Yoga` header
- **Strawberry**: Look for Python-style error traces
- **AWS AppSync**: Look for `x-amzn-*` headers, `"errorType"` in errors
- **Dgraph**: Look for `"extensions":{"touched_uids":...}`
- **graphql-java**: Look for Java stack traces
- **Absinthe (Elixir)**: Look for Elixir/Phoenix patterns

Record identified engine as **INFO** — include engine name and version if found. Not a vulnerability, but useful context.

### Check 23: CDN / WAF Detection (INFO)

Analyze response headers from previous checks:
- `cf-ray`, `cf-cache-status` → **Cloudflare**
- `x-amz-cf-id`, `via: CloudFront` → **AWS CloudFront**
- `x-akamai-*`, `akamai-grn` → **Akamai**
- `x-azure-ref` → **Azure Front Door**
- `x-fastly-request-id` → **Fastly**
- `x-sucuri-id` → **Sucuri WAF**
- `x-aws-waf-*` → **AWS WAF**

Record as **INFO** — not a vulnerability, but useful context for the report.

### Check 24: JWT / Token Analysis (INFO)

If the user provided an Authorization header with a Bearer token:
1. Check if it looks like a JWT (three base64url parts separated by dots)
2. Decode the header (first part) — do NOT decode on an external service, just base64-decode locally
3. Check for:
   - `"alg": "none"` → **CRITICAL** (no signature verification)
   - `"alg": "HS256"` with a guessable secret → **HIGH**
   - Missing `exp` claim in payload → **MEDIUM** (token never expires)
   - `exp` set far in the future (> 1 year) → **LOW** (overly long token lifetime)
4. Note the algorithm, issuer, and expiry (if present) as **INFO**

If no auth token provided, skip this check.

---

## What is NOT a Finding

Do NOT report these as vulnerabilities or key findings:
- **Introspection correctly disabled** — this is expected secure behavior
- **Authentication required** — this is expected behavior (the endpoint correctly blocks unauthenticated requests)
- **Rate limiting active** — this is good security practice
- **Batching disabled** — this is expected
- **Query depth limiting active** — this is expected
- **Subscriptions not available** — this is not a vulnerability

These are evidence that security controls are WORKING, not weaknesses. Never add them to `vulnerabilities[]` or `key_findings[]`.

---

## Phase 3: Individual Query & Mutation Testing (MANDATORY — DO NOT SKIP)

⚠️ **THIS PHASE IS THE MOST IMPORTANT PART OF THE SCAN** ⚠️

Phase 2 only runs generic checks. Phase 3 is where you **actually send real requests to each discovered query and mutation individually** and test them for vulnerabilities.

**If you skip this phase, the scan is WORTHLESS.** Previous scans have been failing because this phase was skipped entirely.

### ⚠️ CRITICAL: NEVER STOP - ALWAYS CONTINUE

- **If ANY request fails with an error → RETRY once with corrected query, then CONTINUE**
- **If ANY request times out → wait 2s and retry once, then CONTINUE**
- **If ANY request returns 429 (rate limited) → add sleep 3s and CONTINUE**
- **NEVER stop testing because of errors** — log the error and move to the next operation
- The scan is INVALID if it doesn't test all selected operations
- A single failed operation should not stop the entire scan

### Step 3.1 — Select Operations to Test

**There is hard cap on how many operations to test. 30 query and 30 mutation operations. Thoroughness beats speed.**

**Query Selection:**
- Review ALL discovered queries
- Give **HIGH PRIORITY** to testing queries that match risk keywords OR take user-supplied arguments (ID, String, input types)
- The ONLY queries you should skip are destructive ones (those explicitly forbidden from testing).
- Do NOT skip other queries; if a query accepts parameters or returns interesting data, it is still worth testing
- When in doubt, test it

**Mutation Selection:**
- Review ALL discovered mutations
- Give **HIGH PRIORITY** to testing mutations that match risk keywords OR take user-supplied arguments
- The ONLY mutations you should skip are destructive ones (those explicitly forbidden from testing).
- Do NOT skip other safe mutations; if a mutation modifies data (and isn't destructive), it is still worth testing but send a wrong id so it does not modify any data
- When in doubt, test it

**Risk Priority for Queries (highest priority first):**

| Priority | Keywords to match in query name |
|----------|----------|
| **CRITICAL** | `admin`, `root`, `superuser`, `owner` |
| **HIGH** | `user`, `viewer`, `profile`, `account`, `auth`, `login`, `token`, `password`, `credential`, `id`, `me`, `self`, `current` |
| **HIGH** | `payment`, `credit`, `card`, `billing`, `invoice`, `money`, `financial`, `balance` |
| **MEDIUM** | `search`, `list`, `fetch`, `get`, `export`, `download`, `all`, `find`, `lookup` |
| **MEDIUM** | `order`, `transaction`, `history`, `log`, `audit`, `create`, `config`, `setting` |

**Risk Priority for Mutations (highest priority first):**

| Priority | Keywords to match in mutation name |
|----------|----------|
| **CRITICAL** | `user`, `admin`, `auth`, `login`, `password`, `reset`, `register`, `signup`, `verify` |
| **HIGH** | `create`, `add`, `new`, `insert`, `set`, `change` |
| **HIGH** | `upload`, `import`, `export`, `execute`, `run`, `submit`, `process` |
| **MEDIUM** | `enable`, `disable`, `toggle`, `approve`, `reject`, `publish`, `unpublish` |
| **MEDIUM** | `send`, `notify`, `email`, `message`, `invite`, `share` |

### Step 3.2 — Test Each Selected Query (ONE BY ONE)

For EACH selected query, you MUST send at least one actual HTTP request. Here's how:

**A) EXTRACT ARGUMENTS AND RETURN FIELDS FROM SCHEMA (MANDATORY):**
Before building ANY query, you MUST look at the introspection result to find:
- The query's input arguments (name and type, e.g., `id: ID!`, `email: String`)
- The return type's fields (e.g., if return type is `User`, what fields does `User` have?)

Example - if introspection shows:
```json
{
  "name": "user",
  "args": [{"name": "id", "type": {"name": "ID"}}],
  "type": {
    "name": "User",
    "fields": [{"name": "id"}, {"name": "email"}, {"name": "name"}]
  }
}
```

Then build: `query { user(id: "1") { id email name } }`

If the query has NO arguments, still request at least 3 fields from the return type.

**B) Send the test request:**
```bash
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"query { <queryName>(<args>) { <fields> } }"}'
# requests_sent += 1  
# Add this query name to queries_tested_names
```

**C) Analyze the response:**
- If validation error (unknown argument, wrong field) → FIX the query using schema info and RETRY once
- If still error after retry → log it and CONTINUE to next query (NEVER stop)
- Did it return data without authentication? → auth bypass finding
- Did it return data for other users (IDOR)? → access control finding
- Did the error message leak sensitive info? → info disclosure finding
- Note the status code and response

**D) If the query accepts string arguments, also test with SQLi payload:**
```bash
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"query { <queryName>(<stringArg>: \"'"'"' OR 1=1--\") { id } }"}'
# requests_sent += 1
```
If this returns a validation error → FIX and RETRY once, then CONTINUE.
If SQLi payload itself causes parse error (not a vulnerability, just bad payload) → skip this specific test and CONTINUE to next operation.

**E) Add the query name to `queries_tested_names` list.**

### Step 3.2b — Skip Destructive/Sensitive Queries

**BEFORE testing any query, check if it contains these keywords:**
- `update`, `delete`, `remove`, `destroy`, `drop`, `ban`, `suspend`, `cancel`, `revoke`, `deactivate`, `execute`, `write`, `edit`

If a query contains ANY of these keywords:
1. **DO NOT send any HTTP request to it**
2. Add it to `queries_skipped` list (NOT to `queries_tested_names`)
3. Continue to the next query

These operations could modify or delete data if accessible without authentication. We skip them to avoid accidental data modification.

### Step 3.3 — Test Each Selected Mutation (ONE BY ONE)

For EACH selected mutation, send at least one actual HTTP request.

**⚠️ ONLY TEST SAFE MUTATIONS** — Skip mutations containing delete/update/remove/drop/ban/suspend/cancel/revoke/deactivate per safety rules above.

**CRITICAL: You must test MANY mutations, not just 2-3. If there are 50+ mutations, test at least 20-30 of them.**

**A) EXTRACT ARGUMENTS AND RETURN FIELDS FROM SCHEMA (MANDATORY):**
Before building ANY mutation, you MUST look at the introspection result to find:
- The mutation's input arguments (name and type, e.g., `email: String!`, `password: String!`)
- The return type's fields (e.g., if return type is `AuthPayload`, what fields does it have?)

Example - if introspection shows:
```json
{
  "name": "login",
  "args": [
    {"name": "email", "type": {"name": "String", "kind": "SCALAR"}},
    {"name": "password", "type": {"name": "String", "kind": "SCALAR"}}
  ],
  "type": {
    "name": "AuthPayload",
    "fields": [{"name": "token"}, {"name": "user"}]
  }
}
```

Then build: `mutation { login(email: "test@test.com", password: "test") { token user } }`

**B) Send WITHOUT auth first (if user provided auth):**
```bash
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"mutation { <mutationName>(<args>) { <fields> } }"}'
# requests_sent += 1
# Add this mutation name to mutations_tested_names
```

**C) Analyze the response:**
- If validation error (unknown argument, wrong field) → FIX the mutation using schema info and RETRY once
- If still error after retry → log it and CONTINUE to next mutation (NEVER stop)
- Did the mutation succeed without auth? → **HIGH** auth bypass
- Did it return detailed error with internal info? → **MEDIUM** info disclosure
- Did it accept the input without validation? → note for report

**D) If mutation has string inputs, test with injection payloads:**
```bash
# SQLi test
curl -s --max-time 30 -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: researchwebconc1-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"mutation { <mutationName>(<stringArg>: \"'"'"' OR 1=1--\") { id } }"}'
# requests_sent += 1
```
If this returns a validation error → FIX and RETRY once, then CONTINUE.

**E) Add the mutation name to `mutations_tested_names` list.**

### Step 3.3b — Skip Destructive/Sensitive Mutations (MANDATORY)

**⚠️ MANDATORY: DO NOT TEST THESE MUTATIONS ⚠️**

Before testing ANY mutation, you MUST check if its name contains any of these keywords:
- `delete`, `remove`, `destroy`, `drop`, `truncate`
- `update`, `edit`, `modify`, `change`, `set`
- `ban`, `suspend`, `cancel`, `revoke`, `deactivate`

If a mutation name contains ANY of these keywords:
1. **DO NOT send any HTTP request to it**
2. Add it to `mutations_skipped` list (NOT to `mutations_tested_names`)
3. Continue to the next mutation

Only test mutations that do NOT contain destructive keywords. This prevents accidental data modification.

**F) IMPORTANT: Test MORE mutations and queries using this rule:**
- If total mutations or queries < 30 → test ALL of them
- If total mutations or queries >= 30 → test at least 70%
- In ALL cases, test maximum 30 mutations

### Step 3.4 — Rate Limiting

- If you get a 429 or rate limit response: **add `sleep 2` or `sleep 3` between requests and CONTINUE testing**
- Do NOT stop or give up when rate limited — slow down and keep going
- Check for `X-RateLimit-*`, `Retry-After` headers
- If `Retry-After` header is present, sleep for that many seconds then resume
- Progressively increase delay if still rate limited: 2s → 5s → 10s
- Do NOT report rate limiting as a finding — it's expected security behavior
- **NEVER skip remaining operations because of rate limiting** — just add delays and continue

---

## Phase 4: Report Generation

After ALL phases complete (including Phase 3), generate the JSON report.

### TRACKING REQUIREMENTS (MUST BE CONSISTENT)

The following MUST match:
- `mutations_tested` (number) MUST equal `len(mutations_tested_names)` (array length)
- `queries_tested` (number) MUST equal `len(queries_tested_names)` (array length)
- `queries_skipped` contains query names NOT tested (update/delete/destroy/remove/drop/ban/suspend)
- `mutations_skipped` contains mutation names NOT tested (update/delete/destroy/remove/drop/ban/suspend)

If they don't match, the scan is INVALID. Go back and fix the counts.

### PRE-REPORT CHECKLIST (verify ALL before generating JSON):

- [ ] `requests_sent` is a real count > 0 (not omitted, not null)
- [ ] `queries_discovered` is a real array of query names from introspection
- [ ] `mutations_discovered` is a real array of mutation names from introspection
- [ ] `testing_coverage` section EXISTS with ALL sub-fields
- [ ] `testing_coverage.queries_tested` is a number > 0
- [ ] `testing_coverage.queries_tested_names` is a non-empty array of actual query names you sent requests to
- [ ] `testing_coverage.mutations_tested` is a number ≥ 0 (0 only if no mutations exist)
- [ ] `testing_coverage.mutations_tested_names` is an array of actual mutation names you sent requests to
- [ ] `testing_coverage.queries_skipped` contains query names with update/delete (NOT tested)
- [ ] `testing_coverage.mutations_skipped` contains mutation names with update/delete (NOT tested)
- [ ] `key_findings` array exists with 3-5 plain-language findings (ONLY real weaknesses)
- [ ] "Introspection disabled" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] "Authentication required" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] "Rate limiting active" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] Introspection enabled severity is **MEDIUM** (NOT CRITICAL)
- [ ] Every vulnerability has `affected_operation` set to the SPECIFIC query/mutation name (NOT generic text like "Any query with aliases")
- [ ] Every vulnerability has `evidence` with real `request`, `response_snippet`, and `status_code`
- [ ] `summary` section has counts for all severity levels
- [ ] `graphql_engine` field is populated (engine name or "unknown")
- [ ] `cdn_waf` field is populated (CDN/WAF name or "none detected")

### JSON Report Format

```json
{
  "scan": {
    "target": "<endpoint_url>",
    "timestamp": "<ISO-8601 timestamp>",
    "duration_seconds": <scan_duration>,
    "requests_sent": <ACTUAL_COUNT_OF_ALL_HTTP_REQUESTS_SENT>,
    "schema_discovered": true|false,
    "graphql_engine": "<detected engine name e.g. 'Apollo Server', 'Hasura', or 'unknown'>",
    "cdn_waf": "<detected CDN/WAF e.g. 'Cloudflare', 'AWS WAF', or 'none detected'>",
    "queries_discovered": ["<query1>", "<query2>", "...ALL query names from schema"],
    "mutations_discovered": ["<mutation1>", "<mutation2>", "...ALL mutation names from schema"],
    "total_queries": <count>,
    "total_mutations": <count>,
    "total_subscriptions": <count>,
    "total_types": <count>
  },
  "testing_coverage": {
    "total_queries_discovered": <number>,
    "queries_tested": <number_of_queries_you_actually_sent_requests_to>,
    "queries_tested_names": ["<query1>", "<query2>", "...ACTUAL names of queries you tested"],
    "queries_skipped": ["<query1>", "<query2>", "...query names with update/delete - NOT tested"],
    "total_mutations_discovered": <number>,
    "mutations_tested": <number_of_mutations_you_actually_sent_requests_to>,
    "mutations_tested_names": ["<mutation1>", "<mutation2>", "...ACTUAL names of mutations you tested"],
    "mutations_skipped": ["<mutation1>", "<mutation2>", "...mutation names with update/delete - NOT tested"],
    "selection_criteria": "<explain how many tested and why — e.g. 'ALL 15 queries tested' or '35 of 80 queries tested (all with args or risk keywords)'"
  },
  "key_findings": [
    "<most important finding 1 in plain language>",
    "<most important finding 2 in plain language>",
    "<finding 3>",
    "<finding 4>",
    "<finding 5>"
  ],
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "<short descriptive title>",
      "category": "<check number and name OR 'Query Testing' OR 'Mutation Testing'>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_estimate": <float 0.0-10.0>,
      "affected_operation": "<SPECIFIC query or mutation name — e.g. 'getUser' not 'Any query'>",
      "summary": "<what happened and what was found - plain language explanation>",
      "evidence": {
        "request": "<exact curl command or HTTP request including URL, headers, body>",
        "response_snippet": "<first ~500 chars of actual response>",
        "status_code": <http_status_code>
      },
      "remediation": "<specific actionable fix>"
    }
  ],
  "summary": {
    "critical": <count>,
    "high": <count>,
    "medium": <count>,
    "low": <count>,
    "info": <count>,
    "total": <total_count>
  }
}
```

### Report Rules

1. **Vulnerability IDs** are sequential: `VULN-001`, `VULN-002`, ...
2. **CVSS estimates**: CRITICAL (9.0-10.0), HIGH (7.0-8.9), MEDIUM (4.0-6.9), LOW (0.1-3.9), INFO (0.0)
3. **Evidence is mandatory** — every vulnerability must have the actual request and response snippet
4. **Response snippets** truncated to ~500 characters
5. **Remediation** must be actionable and specific
6. **`affected_operation`** must be the SPECIFIC query or mutation name (e.g., `getUser`, `createPayment`, `authLogin`) — NEVER use generic text like "Any query with aliases" or "__schema and __type queries"
7. **`requests_sent`** must be an actual count of HTTP requests sent during the scan — NEVER omit this field
8. **`testing_coverage`** section is MANDATORY — if missing, the scan is considered failed
9. **⚠️ ONE VULNERABILITY PER QUERY/MUTATION ⚠️** — When a vulnerability affects multiple queries or mutations (e.g., "missing authentication"), you MUST create a SEPARATE vulnerability entry for EACH affected query or mutation. Do NOT list multiple operations in a single `affected_operation` field. Each query tested without auth should have its own vulnerability entry (e.g., VULN-001 for `user`, VULN-002 for `users`, VULN-003 for `posts`, etc.). Each mutation tested without auth should have its own entry (e.g., VULN-010 for `createUser`, VULN-011 for `createPost`, etc.). Grouping multiple operations into one vulnerability is INVALID.
10. If **no vulnerabilities** found, return empty `vulnerabilities` array and all summary counts at 0
11. **Return raw JSON** — do not wrap in markdown code blocks unless asked

### CVSS Reference

| Severity | CVSS Range | Examples |
|----------|-----------|----------|
| CRITICAL | 9.0–10.0 | SQLi, IDOR with data access, RCE |
| HIGH | 7.0–8.9 | Missing auth, NoSQL injection, mutation abuse, SSRF |
| MEDIUM | 4.0–6.9 | Introspection enabled, query depth abuse, batching, verbose errors |
| LOW | 0.1–3.9 | Field suggestion leak, missing security headers, APQ bypass |
| INFO | 0.0 | Engine fingerprinting, CDN/WAF detection, JWT token info (NOT for "introspection disabled" — that's not a finding at all) |

---

## Error Handling

- **Endpoint unreachable**: Report immediately, do not fabricate results
- **Timeout on a check**: Log it as `"status": "timeout"` in evidence, skip and continue to next check
- **Unexpected response format**: Log the raw response, mark the check as `"status": "inconclusive"`
- **Rate limiting detected**: Add sleep delays between requests (2s → 5s → 10s) and CONTINUE — never stop

---

## File Save

Save scan results to:
`/home/openclaw/.openclaw/workspace/graphql_scans/{full_hostname}.json`

Use the FULL hostname — everything before the first `/` after the protocol:
- `https://edits.nationalmap.gov/apps/graphql` → `edits.nationalmap.gov.json`
- `https://innovationpitch.uefa.com/graphql` → `innovationpitch.uefa.com.json`
- `https://api.example.com/graphql` → `api.example.com.json`

**Do NOT strip subdomains or TLDs.**

---

## Common Mistakes to AVOID

These mistakes have been found in previous scans. DO NOT repeat them:

1. ❌ **Skipping Phase 3** — You MUST test individual queries and mutations, not just run generic checks
2. ❌ **Testing delete/update mutations** — NEVER test mutations containing delete/update/remove/drop/ban/suspend. Only test create mutations. This makes the scan INVALID.
3. ❌ **Grouping multiple queries/mutations in one vulnerability** — Each query and mutation MUST have its own vulnerability entry. Do NOT say "All queries accessible" — create separate VULN-001 for `user`, VULN-002 for `users`, VULN-003 for `posts`, etc. Same for mutations.
4. ❌ **Missing `testing_coverage`** — This section is MANDATORY in every scan output
5. ❌ **Missing `requests_sent`** — Count every HTTP request and include the total
6. ❌ **Generic `affected_operation`** — Use specific names like `getUser`, NOT "Any query with aliases"
7. ❌ **Only 2-3 vulnerabilities** — If you test 20+ operations, you should find more findings (even INFO-level ones)
8. ❌ **Not testing mutations** — Mutations are often the most dangerous; test them individually
9. ❌ **Empty `queries_tested_names`** — Must list the actual query names you sent HTTP requests to
10. ❌ **Empty `mutations_tested_names`** — Must list the actual mutation names you sent HTTP requests to
11. ❌ **Reporting "Introspection disabled" as a finding** — This is EXPECTED secure behavior, NOT a vulnerability. Do not add it to vulnerabilities or key_findings.
12. ❌ **Reporting "Auth required" as a finding** — Requiring authentication is correct behavior, not a weakness.
13. ❌ **Introspection enabled as CRITICAL** — It should be **MEDIUM** severity (CVSS ~5.3). It's info disclosure, not code execution.
14. ❌ **Missing CORS, GET/CSRF, security headers checks** — These are part of the 24-check suite now.
