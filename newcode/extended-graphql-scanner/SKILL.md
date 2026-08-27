---
name: ultimateqlscan
description: Use when scanning or auditing a GraphQL endpoint for vulnerabilities — introspection, batch/alias/depth/DoS queries, SSRF, SQLi, XSS, JWT forge, path traversal, and related GraphQL security tests. Invoke as ultimateqlscan.
---

# Ultimate GraphQL Scanner

When a user provides a GraphQL endpoint URL, execute this full scanning workflow. **Do not skip any phase. Do not skip Phase 3 (Query/Mutation Testing). Every finding must include real evidence.**

> **IMPORTANT — DO NOT SKIP ANYTHING**
>
> Complete **every** phase, **every** Phase 2 check, and **EVERY** discovered query and mutation in Phase 3. There is **no hard cap** and **no prioritization** — test all of them. Do not skip checks because they seem redundant, low priority, time-consuming, already covered, or unlikely to find issues. Do not skip mutations/queries by keyword. Do not stop early after a few findings. Do not substitute “sampling” for full coverage.
>
> **Only allowed omissions:** (1) further DoS-style probes after overload per the DoS budget, (2) a request that is genuinely not callable as GraphQL over HTTP (document why). Everything else MUST be attempted. A scan that skips phases, checks, or operations is **INVALID**.

## Prerequisites

You need the `exec` tool (for curl) or `http` tool to make HTTP requests to the target endpoint. If neither is available, tell the user you cannot scan without HTTP access.

**TIMING / SESSION:**
- **There is NO maximum scan time and NO per-request timeout.** Run to completion no matter how long full coverage takes.
- Do NOT set a per-request `--max-time` — let requests complete even if the server is slow
- Request the longest session timeout available from OpenClaw and extend it as needed; never abort the scan because time is running out
- **Adaptive pacing:** if the server starts responding slowly, insert delays between requests (see Step 3.4) — do not hammer a lagging endpoint

---

## CRITICAL RULES (READ FIRST)

0. **⚠️ IMPORTANT: DO NOT SKIP ANYTHING ⚠️** — Run all phases, all Phase 2 checks, and **every discovered query and mutation** in Phase 3. There is no hard cap and no prioritization — test everything. No shortcuts, no “quick scan,” no skipping “safe-looking” ops, no stopping after first vulns. Only a DoS-budget abort on overload or a genuinely non-callable operation may omit work (document why). Skipping anything else makes the scan **INVALID**.
1. **ALWAYS RESCAN — NEVER USE CACHED RESULTS** — Even if OpenClaw shows "Status: ✅ Active — unchanged" or similar, perform a full fresh scan. Do not check for existing scan files or skip scanning because a previous scan exists. Every scan must be complete and fresh.
2. **YOU MUST ACTUALLY TEST INDIVIDUAL QUERIES AND MUTATIONS** — Not just run generic checks. Phase 3 is MANDATORY.
3. **NO EXCLUSION LISTS — TEST ALL OPERATIONS** — Do NOT skip queries or mutations based on name keywords (`delete`, `update`, `remove`, `destroy`, `drop`, `ban`, `suspend`, etc.). There is no deny/skip list. Prefer non-destructive argument values where possible (bogus IDs, harmless strings), but still send the request and record the result.
4. **EVERY curl/HTTP request you send counts toward `requests_sent`** — Start counting from request #1 and increment for every single request.
5. **The `testing_coverage` section is MANDATORY** in the final JSON — if it's missing, the scan is INCOMPLETE.
6. **Add research headers to EVERY request** — no exceptions.
7. **Each tested query/mutation must appear by name** in `queries_tested_names` or `mutations_tested_names`.
8. **"Introspection disabled" is NOT a finding** — it is expected secure behavior. Do NOT add it to `vulnerabilities` or `key_findings`. (Introspection *enabled* IS a finding — Check 1.)
9. **Only report actual weaknesses** — expected/correct security behavior (introspection disabled, auth required, rate limiting active) should NEVER appear as vulnerabilities. At most, mention them briefly in the scan summary text but never in `vulnerabilities[]` or `key_findings[]`.
10. **CHAIN OPERATIONS** — When a response returns usable artifacts (tokens, session IDs, user IDs, object IDs, cookies, refresh tokens, API keys), store them and reuse them in later requests that need those values. Isolated one-off tests are incomplete.
11. **ADAPTIVE DELAY ON SLOW RESPONSES** — If the server starts delaying (rising latency, near-timeouts, intermittent timeouts), slow down: add `sleep` between requests and increase the delay as latency grows. Never stop the scan because the server is slow — pace it and continue.
12. **RESPECT DoS BUDGET** — Depth/batch/alias/resource/duplication probes must stay within the Phase 2 budget table. Never escalate sizes to knock over the target; abort further DoS checks on 502/503/504 or hard latency spikes.
13. **ALWAYS AUTO-SAVE THE REPORT TO A FILE** — Every scan MUST end by writing the JSON report to `{workspace}/graphql_scans/{full_hostname}.json` and verifying the file exists on disk (Phase 5). Do this automatically without being asked. Printing JSON in chat is NOT saving. A scan whose results were not written to a confirmed file is **INCOMPLETE**.

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
chain_context = {}   # tokens, ids, and other artifacts harvested from responses
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
-H "x-email: random-researcher-at-gmail-dot-com" \
-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

**Do NOT use `--max-time` — allow requests to finish even when the server is slow.**

Send the full introspection query from `skills/ultimateqlscan/templates/introspection.graphql` to the endpoint:

```bash
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
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
- **Try introspection-bypass variations (Check 44)** before giving up:
  - Insert a newline/whitespace inside `__schema` (e.g. `query{__schema\n{queryType{name}}}`)
  - Wrap introspection fields in a fragment
  - Use GET instead of POST, or `Content-Type: application/graphql` / `x-www-form-urlencoded`
  - Try `__type(name: ...)` even when full `__schema` is blocked (Check 7C / 39)
- Attempt field suggestion / `__type` probing + **Clairvoyance-style** iterative field-name fuzzing (Phase 2, Check 7): submit guesses, harvest "Did you mean …?" suggestions, and recurse until the schema is reconstructed (70–90% typical)
- Reuse operation/field names extracted from the app's JS bundles / mobile traffic (embedded queries reveal real operation + field names)
- Continue with whatever operations you can discover
- Note in the scan section: `"schema_discovered": false` (and `"schema_reconstructed": true` if rebuilt via suggestions/bypass)

---

## Phase 2: Generic Vulnerability Checks (46 checks)

Run each check below. For each, record the **exact request**, **response snippet** (truncated to ~500 chars), **status code**, and your determination. **Increment `requests_sent` for each HTTP request.**

**IMPORTANT: Do not skip any check.** Run Checks 1–46 in order (or note DoS-budget abort). “Looks secure,” “already know the answer,” or “saving time” are not reasons to skip.

**NO OPERATION EXCLUSION LIST:** When a check needs a schema field, pick the best match by name/args from the discovered schema. Prefer harmless argument values; do not skip by keyword.

### DoS / resource-abuse budget (MANDATORY)

Checks that stress the server (depth, batch, aliases, resource-intensive, circular fragments, field duplication, directive overloading, login batching) MUST stay within budget so the scan does not knock over the target:

| Limit | Value |
|-------|-------|
| Max alias repetitions per request | **20** (not 50+) |
| Max batch array size | **10** queries |
| Max field duplications per field name | **20** |
| Max nesting depth for deep recursion | **10** levels |
| Max `first`/`limit` for resource-intensive | **100** (not 9999) |
| Max circular/chained fragment depth | **5** fragments |
| Max directives per field (directive overloading) | **20** |
| Max consecutive DoS-style requests | **1 retry** if timeout; then mark and move on |
| If target returns 502/503/504 or latency spikes hard | **STOP further DoS checks**; continue with non-DoS checks only |

Do **not** increase these limits to “be thorough.” Thoroughness for DoS is proving the limit is missing with a bounded probe, not stressing the host.

### Required attack coverage (must attempt when schema allows)

| Attack | Check |
|--------|-------|
| Batch Query Attack | 9 |
| Deep Recursion Query | 6 |
| Resource Intensive Query | 18 |
| Field Duplication Attack | 25 |
| Aliases Based Attack | 11 |
| Circular Fragment | 20 |
| GraphQL Introspection | 1 |
| GraphQL Field Suggestions / `__type` probing | 7 |
| SSRF | 13 |
| Stack Trace Errors | 8 |
| JWT Token Forge | 24 |
| Code Execution | 26 |
| Stored XSS | 27 |
| Log Injection / Log Spoofing | 28 |
| HTML Injection | 29 |
| SQL Injection | 4 |
| Path Traversal | 30 |
| Weak Password / Hash Exposure | 14 |
| Horizontal / Vertical IDOR | 3 |
| Mass Assignment | 33 |
| Privilege Escalation | 34 |
| Command Injection | 35 |
| SSTI / Template Injection | 36 |
| HTTP Verb / Content-Type Confusion | 37 |
| Auth Brute-force via Batch+Alias | 38 |
| `__type` Partial Schema Leak | 7 / 39 |
| Nested / Field-Level Authorization (BOLA/BFLA) | 41 |
| N+1 / Resolver Performance DoS | 42 |
| Query Cost / Complexity Amplification | 43 |
| Introspection Bypass | 44 |
| Cross-Site WebSocket Hijacking | 46 |
| Subscription / WebSocket Abuse | 12 |
| Engine Fingerprint + known CVEs | 22 |
| GraphQL IDE / Voyager Exposure | 45 |

### Check 1: GraphQL Introspection (MEDIUM)

- **Already tested in Phase 1**
- If full schema returned → **MEDIUM** vulnerability
- In production, introspection should be disabled
- Title findings as **GraphQL Introspection**

### Check 2: Missing Authentication (HIGH)

Send a simple query **without** any auth headers:
```graphql
query { __typename }
```
Then try actual schema queries (first 2-3 Query fields) without auth. If they return data → **HIGH**.

### Check 3: IDOR / Broken Access Control — Horizontal & Vertical (CRITICAL)

For queries/mutations that take `id` (or similar) arguments:

**Horizontal IDOR (same role, other user's object):**
- Harvest a resource id belonging to identity A from `chain_context`
- Request that resource with identity B's token (or unauthenticated if possible)
- Try sequential IDs (`1`, `2`, `3`) and UUID variants when schema suggests them
- If another user's data is returned → **CRITICAL**

**Vertical IDOR / privilege boundary:**
- With a low-privilege token, request admin/staff/owner-only operations or fields (`admin`, `internal`, `staff`, elevated role args)
- Compare responses: low-priv vs high-priv (if both tokens exist) vs unauthenticated
- If low-priv obtains elevated data or succeeds on admin mutations → **CRITICAL**

Title findings as **Horizontal IDOR** or **Vertical Privilege Bypass** as appropriate. Include `attack_chain` showing which token/id was reused.

### Check 4: SQL Injection (CRITICAL)

For string-type input arguments, inject standard SQLi payloads:
```
' OR '1'='1
'; SELECT SLEEP(5); --
" OR ""="
1' UNION SELECT null,null,null--
```
**Priority targets:** any query/mutation with String/ID search, filter, content, or lookup arguments from the discovered schema.
Check for: SQL error messages, unexpected data return, different response behavior.
Title findings as **SQL Injection**.

### Check 5: NoSQL Injection (HIGH)

For string inputs, inject NoSQL operators:
```json
{"$gt": ""}
{"$ne": null}
{"$regex": ".*"}
```
Check for: unexpected data return, different response behavior vs normal input.

### Check 6: Deep Recursion Query (MEDIUM)

Send a deeply nested / recursive query (**max 10 levels** — DoS budget) using self-referential types:
```graphql
query {
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}
```
If the server processes it without error or timeout → **MEDIUM** (no depth limiting).
If the target overloads (502/503/timeout storm) → stop further DoS checks; still report if the probe clearly lacked depth limits before overload.
Title findings as **Deep Recursion Query**.

### Check 7: GraphQL Field Suggestions + Wordlist / `__type` Probing (LOW–MEDIUM)

**Always run this check** (whether or not full introspection succeeded). Especially important when `schema_discovered: false`.

**A) Typo / suggestion leaks:**
```graphql
query { usr }
query { uzer }
query { pasword }
query { acount }
```
If errors include "Did you mean …?" → **LOW** (field name disclosure). Use suggested names to expand the discovered operation list.

**B) Wordlist probing (bounded):**
Probe a short common-field wordlist against the root Query (and Mutation if known), max ~30 names total:
`user`, `users`, `viewer`, `node`, `nodes`, `search`, `login`, `account`, `accounts`, `admin`, `config`, `settings`, `files`, `upload`, `posts`, `comments`, `orders`, `products`, `role`, `permissions`, `debug`, `health`, `status`
- Valid field / non-"unknown field" responses → add to discovered ops
- Suggestion-bearing errors → harvest names, then probe those next

**C) `__type` / `__schema` partial leaks (even if full introspection failed):**
```graphql
{ __type(name: "Query") { name fields { name } } }
{ __type(name: "Mutation") { name fields { name } } }
{ __type(name: "User") { name fields { name type { name kind } } } }
{ __schema { queryType { name } mutationType { name } } }
```
If partial type/field lists return → **MEDIUM** (introspection partially bypassed). Feed discovered names into Phase 3.

Title findings as **GraphQL Field Suggestions** or **Partial Introspection via __type**.

### Check 8: Stack Trace Errors (MEDIUM)

Send malformed queries and check error responses for:
- Stack traces
- Internal file paths
- Database names or table names
- Framework/library version info

```graphql
query { __nonexistent }
```
Title findings as **Stack Trace Errors**.

### Check 9: Batch Query Attack (MEDIUM)

Send a batched request (**max 10** queries — DoS budget):
```json
[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]
```
If all execute successfully → **MEDIUM** (no batching limits, enables brute-force/rate-limit bypass).
Title findings as **Batch Query Attack**.

### Check 10: Mutation Abuse (HIGH)

For each discovered mutation (including delete/update/remove — no keyword skip list):
- Attempt to call it **without authentication** (if auth was provided, try without)
- Try with minimal/empty arguments to see error messages
- Prefer bogus IDs / harmless strings as argument values
- If mutations execute without proper auth → **HIGH**

### Check 11: Aliases Based Attack (MEDIUM)

Send a query with many aliases of an expensive operation (**max 20 aliases** — DoS budget):
```graphql
query {
  a1: <expensiveQuery> { id }
  a2: <expensiveQuery> { id }
  a3: <expensiveQuery> { id }
  # ... up to a20 only
}
```
If the server processes all aliases → **MEDIUM** (no alias/complexity limiting).
Title findings as **Aliases Based Attack**.
### Check 12: Subscription / WebSocket Abuse (MEDIUM–HIGH)

If subscriptions exist, test both the HTTP shape and the real WebSocket transport:

**A) HTTP probe:**
```json
{"query": "subscription { <first_subscription_field> { id } }"}
```

**B) WebSocket transport (graphql-ws / subscriptions-transport-ws):**
- Connect to the `ws://` / `wss://` endpoint (same path, or `/subscriptions`) using the `graphql-transport-ws` and legacy `graphql-ws` subprotocols
- Send `connection_init` (with and without an auth token), then `subscribe` / `start`
- Test: **no token**, **expired token**, and **another user's token**

**C) Auth-per-event & scoping:**
- If a subscription streams data without re-validating auth per event, or streams another user's events → **HIGH** (cross-user real-time data leakage)
- Legacy subprotocol handshake bypass (e.g. skipping a completed `connection_init` yet still receiving data, cf. CVE-2026-35523 class) → **HIGH**
- Accepted without any auth → **MEDIUM**

(Cross-site WebSocket hijacking via Origin/cookie is Check 46.)

### Check 13: SSRF (HIGH)

For input fields that accept URL/URI strings — prioritize mutations/queries whose args are typed as URL/URI or named like `url`, `uri`, `href`, `endpoint`, `callback`, `webhook`, `import`, `fetch`:
```graphql
mutation {
  <mutationName>(url: "http://169.254.169.254/latest/meta-data/") {
    <fields>
  }
}
```
Also try localhost and internal metadata URLs from `templates/payloads.md`.
If the server fetches the URL and returns cloud metadata or internal content → **HIGH**.
Title findings as **SSRF**.

### Check 14: Weak Password / Hash Exposure (MEDIUM–HIGH)

Scan the schema and responses for sensitive credential fields:
- `password`, `passwordHash`, `hashedPassword`, `pass_hash`, `hash`
- `token`, `accessToken`, `refreshToken`, `apiKey`, `secret`
- `ssn`, `socialSecurity`, `creditCard`, `cvv`
- `internalId`, `debugInfo`, `adminFlag`

Also:
1. If register/signup/create-user style mutations exist, try a weak password (`123456`, `password`, `admin`)
2. Query current-user / profile / account fields and check whether password hashes or plaintext passwords are returned

If password hashes or plaintext credentials are exposed in responses → **HIGH**.
If weak passwords are accepted → **MEDIUM**.
Title findings as **Weak Password / Hash Exposure**.
### Check 15: CORS Misconfiguration (HIGH)

Send a request with an `Origin` header and check the response:
```bash
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil-attacker.com" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
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
  -H "x-email: random-researcher-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
# requests_sent += 1
If it returns valid data via GET → **MEDIUM** (queries can be triggered via `<img>` tags, links, CSRF).
If mutations also work via GET → **HIGH**.

### Check 17: Automatic Persisted Queries (APQ) Bypass (LOW)

Test if APQ is enabled:
```bash
# Step 1: Try APQ with a hash
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
  -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}'
# requests_sent += 1
```
If APQ is enabled but arbitrary (non-persisted) queries still work alongside → **LOW** (APQ provides no security benefit).

### Check 18: Resource Intensive Query (MEDIUM)

Send a resource-heavy query within DoS budget (`first`/`limit` **≤ 100**, not thousands):
```graphql
query {
  <listQuery>(first: 100) {
    edges {
      node {
        id name email description createdAt updatedAt
        related { id name email description }
      }
    }
  }
}
```
Also try queries that force expensive joins/list sizes when schema args allow (`limit`, `first`, `count`, `pageSize`) — cap at 100.
If the server processes it without cost limiting / timeout protection → **MEDIUM**.
Title findings as **Resource Intensive Query**.

### Check 19: Response Security Headers (LOW)

Check response headers from any previous request for:
- Missing `Content-Type: application/json` (could enable sniffing)
- Missing `X-Content-Type-Options: nosniff`
- Missing `Strict-Transport-Security` (if HTTPS endpoint)
- Missing `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`
- `Server` header leaking version info (e.g., `Server: nginx/1.18.0`)

Report each missing security header as **LOW**. Group them in one vulnerability.

### Check 20: Circular Fragment (MEDIUM)

Send a query with circular/excessive fragment usage (**max 5 chained fragments** — DoS budget) to bypass depth limiting:
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
If circular fragments are accepted (or deeply chained fragments process without limits) → **MEDIUM**.
Title findings as **Circular Fragment**.

### Check 21: Directive Overloading (MEDIUM)

Send a query spamming `@skip`/`@include` directives (**max 20 directives per field** — DoS budget):
```graphql
query {
  <queryName> @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) {
    id
  }
}
```
If the server processes 10+ duplicate directives per field without error → **MEDIUM** (no directive limit).
Title findings as **Directive Overloading**.

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

### Check 24: JWT Token Forge (CRITICAL–HIGH)

If the user provided an Authorization header with a Bearer token:
1. Check if it looks like a JWT (three base64url parts separated by dots)
2. Decode the header (first part) — do NOT decode on an external service, just base64-decode locally
3. Check for:
   - `"alg": "none"` → **CRITICAL** (no signature verification)
   - `"alg": "HS256"` with a guessable secret → **HIGH**
   - Missing `exp` claim in payload → **MEDIUM** (token never expires)
   - `exp` set far in the future (> 1 year) → **LOW** (overly long token lifetime)
4. Note the algorithm, issuer, and expiry (if present) as **INFO**

**JWT Token Forge — always attempt when a current-user / profile / viewer-style query exists in the schema:**
1. Forge a token with `"alg":"none"` and a payload claiming admin/elevated user (e.g. `{"sub":"1","role":"admin"}`) — empty signature segment
2. Forge by mutating claims of a provided JWT (change `sub`/`role`/`userId`) while keeping or stripping the signature
3. Send the discovered current-user query with `Authorization: Bearer <forged_token>`:
```graphql
query { <currentUserQuery> { id email role } }
```
4. If forged token is accepted and returns user data → **CRITICAL**

If no auth token was provided, still attempt `alg:none` forge against any current-user style query when those fields exist.

Title findings as **JWT Token Forge**.

---

### Check 25: Field Duplication Attack (MEDIUM)

Send a query that repeats the same field many times (**max 20 duplicates per field** — DoS budget):
```graphql
query {
  <queryName> {
    id id id id id id id id id id
    name name name name name name name name name name
    email email email email email email email email email email
  }
}
```
If the server accepts and processes heavy duplication without rejection → **MEDIUM**.
Title findings as **Field Duplication Attack**.

### Check 26: Code Execution (CRITICAL)

Look in the schema for dangerous operations whose names or args suggest command/debug execution (`debug`, `eval`, `execute`, `runCommand`, `exec`, `system`, `shell`, or similar).
Probe them with command-like inputs using the actual operation name and args from the schema:
```graphql
mutation {
  <dangerousMutation>(command: "id") {
    <fields>
  }
}
```
Also try: `whoami`, `cat /etc/passwd`, `__import__('os').system('id')` depending on argument type.
If command output or evidence of execution is returned → **CRITICAL**.
Title findings as **Code Execution**.

### Check 27: Stored XSS (HIGH)

For mutations/queries that store and later return user content (create/update of notes, comments, posts, messages, profiles, or other free-text fields):
```graphql
mutation {
  <contentMutation>(content: "<script>alert('xss')</script>") {
    id content
  }
}
```
Also try: `"\"><img src=x onerror=alert(1)>"`, `"javascript:alert(1)"`, `"{{constructor.constructor('alert(1)')()}}"`.
If stored content is returned unescaped / reflected as executable HTML/JS → **HIGH**.
Title findings as **Stored XSS**.

### Check 28: Log Injection / Log Spoofing (MEDIUM)

Inject log-breaking / spoofing payloads into string arguments that may be logged (login email, username, search, message):
```
test@example.com\n[ERROR] admin login success
test\r\nINFO: privilege escalation granted
%0a%0d[CRITICAL] auth bypass
```
```graphql
mutation {
  <authOrLoggableMutation>(email: "victim@example.com\\n[ERROR] Fake successful admin login", password: "x") {
    <fields>
  }
}
```
If responses or subsequent error/log-related fields echo crafted multi-line content as if it were a real log event → **MEDIUM**.
Title findings as **Log Injection / Log Spoofing**.

### Check 29: HTML Injection (MEDIUM–HIGH)

For mutations that accept rich text / HTML / content fields:
```graphql
mutation {
  <contentMutation>(content: "<h1>injected</h1><iframe src='http://evil'></iframe>") {
    id content html
  }
}
```
If HTML is stored and returned without sanitization (especially if a rendered HTML field is present) → **HIGH** if executable context likely, else **MEDIUM**.
Title findings as **HTML Injection**.

### Check 30: Path Traversal (CRITICAL–HIGH)

For mutations/queries that accept file path, filename, or upload path arguments (`path`, `file`, `filename`, `filepath`, upload/read/file-style ops):
```graphql
mutation {
  <fileMutation>(path: "../../../etc/passwd", content: "x") {
    id path url
  }
}
```
Also try:
```
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
/etc/passwd
C:\\Windows\\win.ini
```
If file contents outside the intended directory are returned or written → **CRITICAL**; if path is accepted without traversal rejection but no file leak confirmed → **HIGH**.
Title findings as **Path Traversal**.

### Check 31: Information Disclosure (other sensitive fields) (MEDIUM)

Beyond password hashes (Check 14), flag other sensitive schema fields exposed in responses (`ssn`, `creditCard`, `apiKey`, `privateKey`, `debugInfo`, internal flags). If exposed → **MEDIUM**.

### Check 32: Combined DoS Cross-Check (INFO)

Confirm that Checks 6, 9, 11, 18, 20, 21, 25, and 38 stayed within the DoS budget table and were executed (or skipped after overload). Note budget compliance under evidence as **INFO** (not a vulnerability by itself).

---

### Check 33: Mass Assignment (HIGH–CRITICAL)

For mutations that take input objects (`CreateUserInput`, `UpdateProfileInput`, etc.), send **extra privileged fields not required** (or not documented for that caller), e.g.:
```graphql
mutation {
  <createOrUpdateMutation>(input: {
    name: "test"
    email: "test@example.com"
    role: "admin"
    isAdmin: true
    permissions: ["*"]
    verified: true
    balance: 999999
  }) {
    id role isAdmin
  }
}
```
Adapt extra field names from the input type schema when available; also try common privileged keys even if not listed on that input (some servers accept undeclared keys).
If the object is created/updated with elevated privileges → **CRITICAL**; if extra fields are silently accepted into storage → **HIGH**.
Title findings as **Mass Assignment**.

### Check 34: Privilege Escalation / Admin Field Access (HIGH–CRITICAL)

Once a low-privilege token exists in `chain_context`:
1. Attempt admin-only mutations/queries (names/args suggesting `admin`, `staff`, `internal`, role changes)
2. Request sensitive fields on the current-user type: `role`, `permissions`, `isAdmin`, `flags`
3. Try mutations that change role/permissions on self or another user id
4. Compare with unauthenticated and (if available) admin token responses

If low-priv succeeds where only admin should → **CRITICAL**.
Title findings as **Privilege Escalation**.

### Check 35: Command Injection (CRITICAL)

For **any** string arguments (not only debug ops), try OS command metacharacters:
```
; id
| id
$(id)
`id`
& whoami
```
```graphql
mutation {
  <mutationName>(<stringArg>: "; id") { <fields> }
}
```
Signals: command output in response, unusual delays correlating with `sleep`, shell errors.
If command execution evidence appears → **CRITICAL**.
Title findings as **Command Injection**.

### Check 36: SSTI / Template Injection (HIGH–CRITICAL)

For content/template/message/email body string fields:
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{self}}
```
```graphql
mutation {
  <contentMutation>(content: "{{7*7}}") { id content rendered html }
}
```
If the response renders `49` or leaks template engine internals → **HIGH** (or **CRITICAL** if code exec primitives work).
Title findings as **SSTI / Template Injection**.

### Check 37: HTTP Verb / Content-Type Confusion (MEDIUM–HIGH)

Probe the same GraphQL query using alternate verbs and content types:

1. `POST` + `Content-Type: application/graphql` with raw query body (not JSON)
2. `POST` + `Content-Type: application/x-www-form-urlencoded` (`query=...`)
3. `PUT` / `POST` with JSON body (if PUT unusual for the API)
4. Confirm GET query support already covered in Check 16

If mutations execute via GET or odd content-types enable CSRF / cache / WAF bypass → **HIGH**; if only queries work via alternate type → **MEDIUM**.
Title findings as **HTTP Verb / Content-Type Confusion**.

### Check 38: Auth Brute-force via Batch + Alias (HIGH)

If a login/auth mutation exists, attempt **bounded** credential spraying using batch **or** aliases (respect DoS budget: ≤10 batch entries **or** ≤20 aliases — pick one technique, not both stacked to huge sizes):
```graphql
mutation {
  a1: <loginMutation>(email: "admin@target.com", password: "admin") { token }
  a2: <loginMutation>(email: "admin@target.com", password: "password") { token }
  a3: <loginMutation>(email: "admin@target.com", password: "123456") { token }
}
```
Also try a JSON array batch of ≤10 login attempts.
If many attempts are evaluated in one HTTP round-trip without lockout/rate-limit → **HIGH** (auth brute-force amplifier).
Use only a tiny password list (≤10). Do not run large dictionaries.
Title findings as **Auth Brute-force via Batch/Alias**.

### Check 39: `__type` Partial Schema Leak (MEDIUM)

Dedicated confirmation when full introspection is blocked but `__type(name: ...)` or limited `__schema` fields still return type metadata (see Check 7C). If confirmed → **MEDIUM**.
Title findings as **Partial Introspection via __type**.

### Check 40: Authorization Matrix Spot-Check (HIGH–CRITICAL)

Build a mini matrix for 3–5 sensitive operations:
| Operation | No auth | Low-priv token | Other-user token | Admin token (if any) |
If any cell allows access it should not → file a per-operation finding with `attack_chain`.
This consolidates Checks 3 and 34 with chaining — do not skip if tokens/ids were harvested.

### Check 41: Nested / Field-Level Authorization — BOLA/BFLA (CRITICAL)

**This is the single most common serious GraphQL finding.** Object-level auth on a top-level query often does NOT protect nested resolvers that hydrate related types.

1. For each protected type, reach its sensitive fields **through relationship traversal**, not just direct access. Example: `order` may be guarded, but `order.customer` / `order.customer.paymentMethods` runs its own unguarded resolver:
```graphql
query { order(id: "<otherUsersOrderId>") { id customer { id email paymentMethods { last4 } } } }
```
2. Walk the graph **field by field under each role** (no auth, low-priv, other-user, admin). A field protected via one path may be exposed via another.
3. **BFLA:** call every sensitive mutation (e.g. `deleteUser`, `refundPayment`) with a normal/low-priv token. If the resolver runs → function-level check missing → **CRITICAL**.
4. Map which fields are protected, which are not, and where nested gaps exist.

**False-positive guard:** a `200` with `{"errors":[{"message":"Not authorized"}]}` is **enforced**, not bypassed — read the body, not just the status. Report only when protected data is actually returned.
Title findings as **Nested Authorization Bypass (BOLA)** or **Function-Level Auth Bypass (BFLA)**.

### Check 42: N+1 / Resolver Performance DoS (MEDIUM)

Identify resolvers that trigger one backend call per item (N+1 antipattern):
- Query a list with a nested related field: `{ <listQuery>(first: 100) { id <relation> { id } } }`
- Measure execution time vs. a flat query of the same size
- If per-item nested resolution causes response time to scale linearly/steeply (clear N+1) → **MEDIUM** (amplifiable DoS)
Stay within the DoS budget (`first ≤ 100`); abort on overload.
Title findings as **N+1 Resolver DoS**.

### Check 43: Query Cost / Complexity Amplification (MEDIUM)

Test whether cost/complexity limits exist and whether they can be bypassed:
1. **Static vs dynamic:** determine if complexity is scored before execution (rejected instantly) or only caught after a timeout
2. **Under-limit-but-expensive:** craft a query that stays under any depth limit yet is costly (wide field selection + several moderately expensive relations)
3. **Fragment-spread amplification:** reference the same fragment many times to multiply cost while keeping the query text small (respect DoS budget: ≤5 fragment depth, ≤20 spreads)
If expensive queries execute without cost rejection → **MEDIUM** (no query-cost analysis).
Title findings as **Query Cost Amplification**.

### Check 44: Introspection Bypass (MEDIUM)

When standard `__schema` introspection is blocked, retry with evasions:
- Whitespace/newline inside the introspection query
- Introspection fields wrapped in a fragment
- Alternate transport: GET, `Content-Type: application/graphql`, `application/x-www-form-urlencoded`
- `__type(name: ...)` when `__schema` is blocked (see Check 39)
If any variation returns schema/type data that the default request refused → **MEDIUM** (introspection filtering bypassable).
Title findings as **Introspection Bypass**.

### Check 45: GraphQL IDE / Voyager Exposure (LOW–MEDIUM)

On the given endpoint's host, check whether developer tooling is reachable unauthenticated in production:
```
GET /graphiql   GET /graphql/playground   GET /playground
GET /voyager    GET /graphql/voyager
```
If an interactive console or schema visualizer loads without auth → **LOW–MEDIUM** (recon/schema exposure).
Title findings as **GraphQL IDE Exposure**.

### Check 46: Cross-Site WebSocket Hijacking (HIGH)

For subscription WebSocket endpoints that authenticate via **cookies** (not explicit tokens):
1. Open the WS handshake with a forged/foreign `Origin` header
2. If the handshake succeeds without validating `Origin` and relies on ambient cookies, a cross-site page could subscribe as the victim → **HIGH** (real-time data exfiltration)
Test alongside Check 12. Report only if a cross-origin connection is actually accepted and streams data.
Title findings as **Cross-Site WebSocket Hijacking**.

---

## What is NOT a Finding

Do NOT report these as vulnerabilities or key findings:
- **Introspection correctly disabled** — this is expected secure behavior
- **Authentication required** — this is expected behavior (the endpoint correctly blocks unauthenticated requests)
- **Rate limiting active** — this is good security practice
- **Batching disabled** — this is expected
- **Query depth limiting active** — this is expected
- **Subscriptions not available** — this is not a vulnerability
- **GraphQL parse/validation errors alone** — not SQLi/SSTI/command injection (need behavioral evidence)
- **DoS probe rejected by complexity/depth limits** — controls working; not a finding
- **Server overload from exceeding budget** — scanner misconfig; do not file as target vuln without a bounded successful probe
- **`{"errors":[{"message":"Not authorized"}]}` (even with HTTP 200)** — authorization is ENFORCED, not bypassed. Always read the response body, not just the status code. Only report auth bypass when protected data is actually returned.

These are evidence that security controls are WORKING, not weaknesses. Never add them to `vulnerabilities[]` or `key_findings[]`.

---

## Phase 3: Individual Query & Mutation Testing (MANDATORY — DO NOT SKIP)

⚠️ **THIS PHASE IS THE MOST IMPORTANT PART OF THE SCAN** ⚠️

Phase 2 only runs generic checks. Phase 3 is where you **actually send real requests to each discovered query and mutation individually** and test them for vulnerabilities.

**If you skip this phase, the scan is WORTHLESS.** Previous scans have been failing because this phase was skipped entirely.

### ⚠️ CRITICAL: NEVER STOP - ALWAYS CONTINUE

- **If ANY request fails with an error → RETRY once with corrected query, then CONTINUE**
- **If ANY request times out → wait 2s and retry once, then CONTINUE** (also raise inter-request delay — see Step 3.4)
- **If ANY request returns 429 (rate limited) → add sleep 3s and CONTINUE**
- **If responses start getting slower → add/increase sleep between requests and CONTINUE**
- **NEVER stop testing because of errors or slowdowns** — log the issue, pace requests, and move on
- The scan is INVALID if it doesn't test all selected operations
- A single failed operation should not stop the entire scan

### Step 3.0 — Chain Operations (MANDATORY)

**Do not treat each query/mutation as an isolated test.** Harvest useful values from every successful (or partially successful) response and feed them into later operations.

#### Maintain a live `chain_context`

After each response, extract and store anything reusable, for example:
- Auth: `token`, `accessToken`, `refreshToken`, `session`, `jwt`, `apiKey`
- Identity: `userId`, `id`, `accountId`, `orgId`, `teamId`
- Objects: `orderId`, `postId`, `fileId`, `resourceId`, or any returned entity `id`
- Other secrets: invite codes, reset tokens, signed URLs, CSRF/nonce values

Update `chain_context` continuously. Prefer the newest valid value when a key is refreshed.

#### How to chain

1. **Auth first when possible** — Prefer testing login/register/auth-style mutations early so later ops can use a real credential.
2. **Reuse credentials** — If a response returns a token/session/key and later ops need auth, replay it using the correct scheme (see **Auth Schemes** below), not just `Authorization: Bearer`.
3. **Reuse IDs** — If query A returns a user/object id and query B requires that id as an argument, call B with the harvested id (also try adjacent/other users' ids for IDOR).
4. **Create → read → escalate** — If a create/upload mutation returns an id, immediately query/fetch that resource; then try access with/without auth and with another user's token if available.
5. **Re-test gated ops** — If an operation failed earlier with "unauthorized" / "authentication required", **retry it** once `chain_context` has a token.
6. **Cross-user chaining** — If you obtain tokens for more than one identity (or can register twice), use token A against resources owned by B to test broken access control.
7. **Document the chain** — In vulnerability evidence, show the sequence: which prior operation produced the token/id, and which later request reused it.

#### Example flow (adapt names from the real schema)

```
1) mutation { <loginOrRegister>(...) { token user { id } } }
   → chain_context.token = <token>, chain_context.userId = <id>

2) query with Authorization: Bearer <token>
   { <currentUserQuery> { id email role } }

3) query { <resourceByUser>(userId: "<userId>") { ... } }
   → also try other ids for IDOR

4) mutation { <createSomething>(...) { id } }
   → chain_context.resourceId = <id>

5) query { <getSomething>(id: "<resourceId>") { ... } }
   → retry without token / with another token
```

**Chaining is required whenever artifacts are available.** Skipping reuse of a returned token or id makes the scan incomplete.

#### Auth Schemes (do NOT assume Bearer)

GraphQL APIs authenticate in several ways. Detect which scheme the target uses (from the login response shape, `Set-Cookie` headers, docs, or the header the user provided) and replay the harvested credential with the **matching** scheme. Try more than one if unsure.

| Scheme | How to send | When it applies |
|--------|-------------|-----------------|
| Bearer / JWT | `-H "Authorization: Bearer <token>"` | Response returns a `token` / `accessToken` / JWT |
| Raw token | `-H "Authorization: <token>"` (no `Bearer`) | Some APIs use the token directly |
| Cookie / session | `-H "Cookie: <name>=<value>"` (echo `Set-Cookie` from login), or `curl -c jar.txt` / `-b jar.txt` | Login sets a session cookie |
| API key header | `-H "X-API-Key: <key>"` (also `apikey`, `x-api-key`, `api-key`) | Response/docs expose an API key |
| Custom header | `-H "<custom>: <value>"` (e.g. `X-Auth-Token`, `X-Access-Token`, `X-Hasura-Admin-Secret`) | Engine/app-specific (e.g. Hasura) |
| GraphQL-in-body | some APIs take auth as a query/mutation argument or in `extensions` | login/refresh mutations |

Store the detected scheme + credential in `chain_context` (e.g. `chain_context.auth = {scheme: "cookie", header: "Cookie: sid=..."}`) and apply it consistently on every authed request. Preserve any auth header/token the **user** supplied and reuse it the same way.

### Step 3.1 — Operations to Test

**Test EVERY discovered query and EVERY discovered mutation. There is NO hard cap and NO prioritization — full coverage is required.**

- Review ALL discovered queries and mutations — **no keyword exclusion list, no priority ranking**
- Test each one; do NOT skip any because its name contains `delete`/`update`/`remove`/etc. or because it looks low-risk
- Prefer bogus IDs / harmless strings so real data is less likely to change, but **still send the request**
- The only operations you may leave untested are ones that are genuinely not callable as GraphQL over HTTP (document why)

### Step 3.2 — Test Each Query (ONE BY ONE)

For EACH discovered query, you MUST send at least one actual HTTP request. Here's how:

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

**B) Send the test request** (include any auth from `chain_context` — see Auth Schemes below):
```bash
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
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
- **Harvest for chaining:** if the response contains tokens, user/object ids, or other reusable values → store them in `chain_context` and use them on subsequent requests
- Note the status code and response

**D) If the query accepts string arguments, also test with SQLi payload:**
```bash
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"query { <queryName>(<stringArg>: \"'"'"' OR 1=1--\") { id } }"}'
# requests_sent += 1
```
If this returns a validation error → FIX and RETRY once, then CONTINUE.
If SQLi payload itself causes parse error (not a vulnerability, just bad payload) → skip this specific test and CONTINUE to next operation.

**E) Add the query name to `queries_tested_names` list.**

### Step 3.2b — No Skipping

**There is no keyword exclusion list and no cap.** Do not skip queries because they contain `update`, `delete`, `remove`, `destroy`, `drop`, `ban`, `suspend`, `execute`, `write`, or `edit`, and do not stop after some number of operations. Test every discovered query. The only query you may leave untested is one that is genuinely not callable as GraphQL over HTTP (document why).

### Step 3.3 — Test Each Mutation (ONE BY ONE)

For EACH discovered mutation, send at least one actual HTTP request.

**Test ALL mutations — including delete/update/remove.** Prefer bogus IDs and harmless strings to reduce side effects, but do not skip by keyword.

**CRITICAL: You must test EVERY mutation, not just a few. If there are 50+ mutations, test all 50+.**

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
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"mutation { <mutationName>(<args>) { <fields> } }"}'
# requests_sent += 1
# Add this mutation name to mutations_tested_names
```
Then, if a token/credential is available in `chain_context`, send the same mutation **with** auth to compare authed vs unauthed behavior (use the correct Auth Scheme below).

**C) Analyze the response:**
- If validation error (unknown argument, wrong field) → FIX the mutation using schema info and RETRY once
- If still error after retry → log it and CONTINUE to next mutation (NEVER stop)
- Did the mutation succeed without auth? → **HIGH** auth bypass
- Did it return detailed error with internal info? → **MEDIUM** info disclosure
- Did it accept the input without validation? → note for report
- **Harvest for chaining:** store any returned `token` / ids / created resource ids in `chain_context`; immediately follow with dependent queries that need those values

**D) If mutation has string inputs, test with injection payloads:**
```bash
# SQLi test
curl -s -X POST "<ENDPOINT>" \
  -H "Content-Type: application/json" \
  -H "x-info: This-is-a-scanner-for-research" \
  -H "x-email: random-researcher-at-gmail-dot-com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{"query":"mutation { <mutationName>(<stringArg>: \"'"'"' OR 1=1--\") { id } }"}'
# requests_sent += 1
```
If this returns a validation error → FIX and RETRY once, then CONTINUE.

**E) Add the mutation name to `mutations_tested_names` list.**

### Step 3.3b — No Skipping for Mutations

**There is no mutation exclusion / deny list and no cap.** Do NOT skip mutations because the name contains `delete`, `remove`, `destroy`, `drop`, `truncate`, `update`, `edit`, `modify`, `change`, `set`, `ban`, `suspend`, `cancel`, `revoke`, or `deactivate`, and do not stop after some number of operations. Test every discovered mutation. The only mutation you may leave untested is one that is genuinely not callable as GraphQL over HTTP (document why).

**F) IMPORTANT: Test EVERY query and EVERY mutation — 100% coverage. No cap, no sampling, no prioritization.**

### Step 3.4 — Rate Limiting & Adaptive Delay

Track recent response latency (wall-clock time per request). Adjust pacing dynamically:

**Triggers to slow down:**
- HTTP `429` or explicit rate-limit / throttle messages
- `Retry-After`, `X-RateLimit-*` headers
- Response time rising (e.g. was <1s, now regularly >3–5s)
- Timeouts, near-timeouts, or intermittent connection resets under load
- Server errors that look like overload (`502` / `503` / `504`)

**What to do:**
- Maintain an inter-request delay `request_delay_seconds` (start at `0`)
- On any trigger above: set delay to at least `2`, then escalate `2s → 5s → 10s → 15s` if slowness continues
- After each request: `sleep $request_delay_seconds` before the next one
- If `Retry-After` is present, sleep that many seconds (or the higher of Retry-After vs current delay)
- On timeout: sleep, retry once, then CONTINUE with a higher delay
- If latency recovers (several fast responses in a row), you may gradually reduce the delay, but prefer staying conservative
- Do NOT report rate limiting or server slowdown as a vulnerability — pace and continue
- **NEVER skip remaining operations because of rate limiting or slow responses** — just add delays and continue

### Step 3.5 — Chained Re-test Pass

After the main query/mutation loops, if `chain_context` gained tokens or ids during the scan:
1. Re-run operations that previously failed for missing auth, now with the harvested token
2. Re-run id-based lookups using harvested entity ids
3. Compare privileged vs unprivileged responses and record new findings with chain evidence
4. Run **horizontal IDOR**: token A against resource ids owned by B (and the reverse)
5. Run **vertical checks**: low-priv token against admin-only ops/fields (Checks 3, 34, 40)
6. Re-try mass-assignment mutations (Check 33) authenticated if create required auth

---

## Phase 4: Report Generation

After ALL phases complete (including Phase 3), generate the JSON report.

### TRACKING REQUIREMENTS (MUST BE CONSISTENT)

The following MUST match:
- `mutations_tested` (number) MUST equal `len(mutations_tested_names)` (array length)
- `queries_tested` (number) MUST equal `len(queries_tested_names)` (array length)
- `queries_tested_names` SHOULD cover ALL of `queries_discovered` (and mutations likewise) — anything untested must be a genuinely non-callable operation, noted in `coverage_summary`

If they don't match, the scan is INVALID. Go back and fix the counts.

### PRE-REPORT CHECKLIST (verify ALL before generating JSON):

- [ ] **Full coverage** — all phases + Phase 2 checks attempted; EVERY discovered query and mutation tested (no cap, no prioritization); any untested op is genuinely non-callable and documented
- [ ] `requests_sent` is a real count > 0 (not omitted, not null)
- [ ] `queries_discovered` is a real array of query names from introspection
- [ ] `mutations_discovered` is a real array of mutation names from introspection
- [ ] `testing_coverage` section EXISTS with ALL sub-fields
- [ ] `testing_coverage.queries_tested` is a number > 0
- [ ] `testing_coverage.queries_tested_names` is a non-empty array of actual query names you sent requests to
- [ ] `testing_coverage.mutations_tested` is a number ≥ 0 (0 only if no mutations exist)
- [ ] `testing_coverage.mutations_tested_names` is an array of actual mutation names you sent requests to
- [ ] `queries_tested_names` / `mutations_tested_names` cover ALL discovered operations (no cap, no keyword/priority skips)
- [ ] Required attack checks covered when schema allows (incl. IDOR horizontal/vertical, **nested/field-level BOLA/BFLA**, mass assignment, priv esc, command injection, SSTI, verb/content-type confusion, auth batch brute-force, `__type` probing, introspection bypass, N+1/cost amplification, subscription/WebSocket + cross-site WS hijacking)
- [ ] IDE/Voyager exposure checked (Check 45); engine fingerprint + known-CVE note (Check 22)
- [ ] Every finding has `owasp_api` set (OWASP API Top 10 mapping)
- [ ] Operation chaining performed when responses returned tokens/ids (reused in later requests; auth-gated ops re-tested)
- [ ] DoS checks stayed within budget (aliases≤20, batch≤10, depth≤10, first≤100, field dup≤20)
- [ ] Every vulnerability includes `attack_chain` when the finding depended on prior steps (token/id harvest → exploit)
- [ ] Duplicate findings merged per dedup rules (same title + affected_operation + root cause → one entry)
- [ ] `key_findings` array exists with 3-5 plain-language findings (ONLY real weaknesses)
- [ ] "Introspection disabled" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] "Authentication required" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] "Rate limiting active" is NOT in `vulnerabilities[]` or `key_findings[]`
- [ ] Introspection enabled severity is **MEDIUM** (NOT CRITICAL)
- [ ] Every vulnerability has `affected_operation` set to the SPECIFIC query/mutation name (NOT generic text like "Any query with aliases")
- [ ] Every vulnerability has `evidence` with real `request`, `response_snippet`, and `status_code`
- [ ] **Report written to `{workspace}/graphql_scans/{full_hostname}.json` AND verified on disk (non-empty)** — auto-saved without the user asking (Phase 5)
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
    "schema_reconstructed": true|false,
    "ide_exposed": "<none | GraphiQL | Playground | Voyager>",
    "graphql_engine": "<detected engine name e.g. 'Apollo Server', 'Hasura', or 'unknown'>",
    "engine_version": "<version if exposed, else 'unknown'>",
    "known_cves": ["<CVE ids relevant to detected engine/version, if any>"],
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
    "total_mutations_discovered": <number>,
    "mutations_tested": <number_of_mutations_you_actually_sent_requests_to>,
    "mutations_tested_names": ["<mutation1>", "<mutation2>", "...ACTUAL names of mutations you tested"],
    "not_callable": ["<op>", "...ONLY operations that could not be called over HTTP, with reason — should normally be empty"],
    "coverage_summary": "<must confirm FULL coverage — e.g. 'ALL 15 queries and ALL 22 mutations tested' — note any not_callable ops and any DoS checks aborted due to overload>"
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
      "owasp_api": "<OWASP API Top 10 category, e.g. 'API1:2023 BOLA', 'API5 BFLA', 'API4 Resource Consumption', 'API8 Misconfiguration', or 'N/A'>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_estimate": <float 0.0-10.0>,
      "affected_operation": "<SPECIFIC query or mutation name — e.g. 'getUser' not 'Any query'>",
      "summary": "<what happened and what was found - plain language explanation>",
      "attack_chain": [
        "<step 1: e.g. login as user A → harvested token>",
        "<step 2: e.g. create resource → harvested resourceId>",
        "<step 3: e.g. access resourceId with user B token → data returned>"
      ],
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

Use `"attack_chain": []` only when the finding is a single isolated request with no prior dependency.

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
11. **Return raw JSON** — do not wrap in markdown code blocks unless asked. **After generating it, you MUST save it to a file (Phase 5) — displaying it here does not count as saving.**
12. **`attack_chain` is mandatory for chained findings** — list the ordered steps (harvest → reuse → exploit). Single-request findings may use an empty array.
13. **Dedup rules** — Before finalizing the report, merge duplicates:
    - Same `title` + same `affected_operation` + same root cause → **one** vulnerability (keep strongest evidence / fullest `attack_chain`)
    - Chained re-test rediscovering the same auth bypass already filed → **do not** add a second entry; append to `attack_chain` / evidence instead
    - Same check hitting many nearly identical ops still gets **one entry per operation** (rule 9), but not multiple entries per operation from chaining retries
14. **DoS budget compliance** — note in `testing_coverage.coverage_summary` if any DoS checks were aborted due to overload
15. **`owasp_api` per finding** — map every vulnerability to its OWASP API Top 10 category using the table below (`N/A` only for pure INFO items)
16. **Read the body, not the status** — never mark auth-bypass on a `200` that contains `{"errors":[{"message":"Not authorized"}]}`; only when protected data is actually returned

### CVSS Reference

| Severity | CVSS Range | Examples |
|----------|-----------|----------|
| CRITICAL | 9.0–10.0 | SQLi, IDOR/BOLA with data access, nested/field-level auth bypass, BFLA on sensitive mutation, RCE / code execution, JWT forge accepted, path traversal, mass assignment to admin, command injection |
| HIGH | 7.0–8.9 | Missing auth, NoSQL injection, mutation abuse, SSRF, Stored XSS, hash exposure, privilege escalation, auth batch brute-force, SSTI, cross-user subscription/WS leakage, cross-site WS hijacking |
| MEDIUM | 4.0–6.9 | Introspection enabled, deep recursion, batch query, aliases, circular fragment, directive overloading, field duplication, resource intensive, N+1 DoS, query cost amplification, verbose/stack errors, log/HTML injection, `__type` partial leak, introspection bypass, content-type confusion |
| LOW | 0.1–3.9 | Field suggestions, missing security headers, APQ bypass, GraphQL IDE/Voyager exposure |
| INFO | 0.0 | Engine fingerprinting, CDN/WAF detection, JWT token info (NOT for "introspection disabled" — that's not a finding at all) |

### OWASP API Top 10 Mapping (set `owasp_api` per finding)

| Finding class | OWASP API |
|---------------|-----------|
| IDOR / BOLA / nested object auth | **API1** Broken Object Level Authorization |
| Missing/broken auth, JWT forge | **API2** Broken Authentication |
| Excessive data exposure, hash/PII leak, mass assignment (read-back) | **API3** Broken Object Property Level Authorization |
| Depth/complexity/batch/alias/N+1 DoS, no rate limit | **API4** Unrestricted Resource Consumption |
| BFLA, privilege escalation, admin mutations | **API5** Broken Function Level Authorization |
| Business-logic mutation abuse | **API6** Unrestricted Access to Sensitive Business Flows |
| SSRF | **API7** Server Side Request Forgery |
| Introspection enabled, verbose errors, IDE exposure, CORS/CSRF, misconfig | **API8** Security Misconfiguration |
| Injection (SQL/NoSQL/command/SSTI/XSS/log/path) | mapped to **API8**/injection |

---

## Error Handling

- **Endpoint unreachable**: Report immediately, do not fabricate results
- **Timeout on a check**: Log it as `"status": "timeout"` in evidence, increase inter-request delay, retry once, then skip and continue to next check
- **Server responses getting slower**: Raise `request_delay_seconds` (2s → 5s → 10s → 15s), keep scanning
- **Unexpected response format**: Log the raw response, mark the check as `"status": "inconclusive"`
- **Rate limiting detected**: Add sleep delays between requests (2s → 5s → 10s → 15s) and CONTINUE — never stop

---

## Phase 5: Save Results (MANDATORY — ALWAYS AUTO-SAVE)

⚠️ **You MUST write the JSON report to a file. This is NOT optional and NOT dependent on the user asking.** Every scan run auto-saves, even if you also print the JSON in chat, even if the scan found nothing, even if the scan was partial/interrupted (save what you have).

### Steps (do ALL, in order)

1. **Resolve the workspace path** — the current OpenClaw / agent workspace directory (NOT a hardcoded host path). If unsure, use the directory the agent is running in.
2. **Create the output directory** if missing: `{workspace}/graphql_scans/`
   ```bash
   mkdir -p "{workspace}/graphql_scans"
   ```
3. **Write the file** to:
   ```
   {workspace}/graphql_scans/{full_hostname}.json
   ```
   Use the actual file-write tool/command — do not just display the JSON and assume it's saved.
4. **VERIFY the write succeeded** — immediately read back / stat the file and confirm it exists and is non-empty:
   ```bash
   ls -l "{workspace}/graphql_scans/{full_hostname}.json" && wc -c "{workspace}/graphql_scans/{full_hostname}.json"
   ```
   If the file is missing or empty → **retry the save** (try an absolute path, then a fallback path) until it is confirmed on disk.
5. **Report the saved path** to the user in your summary (e.g. "Saved to `.../graphql_scans/api.example.com.json`").

### Filename rule

Use the FULL hostname — everything before the first `/` after the protocol:
- `https://api.example.com/graphql` → `api.example.com.json`

**Do NOT strip subdomains or TLDs.**

### Examples
- Workspace `/home/bormaa/.openclaw/workspace-agent2` → `/home/bormaa/.openclaw/workspace-agent2/graphql_scans/api.example.com.json`
- Workspace `/home/openclaw/.openclaw/workspace` → `/home/openclaw/.openclaw/workspace/graphql_scans/api.example.com.json`

### Fallbacks (if the workspace write fails)
- Retry with an absolute workspace path
- If still failing, save to `./graphql_scans/{full_hostname}.json` in the current directory
- As a last resort, save to `/tmp/graphql_scans/{full_hostname}.json` and clearly tell the user where it went
- **Never end the scan without a confirmed saved file.**

---

## Common Mistakes to AVOID

These mistakes have been found in previous scans. DO NOT repeat them:

0. ❌ **Skipping anything** — Do not skip phases, Phase 2 checks, or in-scope operations. “Quick scan,” “redundant,” or “low priority” are invalid excuses. Incomplete coverage = INVALID scan.
1. ❌ **Skipping Phase 3** — You MUST test individual queries and mutations, not just run generic checks
2. ❌ **Using a keyword exclusion / deny-list** — Do NOT skip `delete`/`update`/`remove`/etc. There is no exclusion list. Prefer bogus IDs, but still test.
3. ❌ **Grouping multiple queries/mutations in one vulnerability** — Each query and mutation MUST have its own vulnerability entry. Do NOT say "All queries accessible" — create separate VULN-001 for `user`, VULN-002 for `users`, VULN-003 for `posts`, etc. Same for mutations.
4. ❌ **Missing `testing_coverage`** — This section is MANDATORY in every scan output
5. ❌ **Missing `requests_sent`** — Count every HTTP request and include the total
6. ❌ **Generic `affected_operation`** — Use specific names like `getUser`, NOT "Any query with aliases"
7. ❌ **Only 2-3 vulnerabilities** — If you test 20+ operations, you should find more findings (even INFO-level ones)
8. ❌ **Not testing mutations** — Mutations are often the most dangerous; test them individually
9. ❌ **Empty `queries_tested_names`** — Must list the actual query names you sent HTTP requests to
10. ❌ **Empty `mutations_tested_names`** — Must list the actual mutation names you sent HTTP requests to
11. ❌ **Reporting "Introspection disabled" as a finding** — This is EXPECTED secure behavior, NOT a vulnerability. Do not add it to vulnerabilities or key_findings. (Introspection *enabled* IS a finding.)
12. ❌ **Reporting "Auth required" as a finding** — Requiring authentication is correct behavior, not a weakness.
13. ❌ **Introspection enabled as CRITICAL** — It should be **MEDIUM** severity (CVSS ~5.3). It's info disclosure, not code execution.
14. ❌ **Missing required attack checks** — Include IDOR (horizontal/vertical), mass assignment, privilege escalation, command injection, SSTI, verb/content-type confusion, auth batch/alias brute-force, and `__type`/wordlist probing when schema allows — plus the existing DoS/injection suite.
15. ❌ **Skipping Field Suggestions because introspection worked** — Always run GraphQL Field Suggestions / wordlist / `__type` probing (Check 7).
16. ❌ **Hardcoding demo operation names** — Always discover real operation names from the schema; never assume specific mutation/query names.
17. ❌ **Not chaining operations** — If a response returns a token, user id, or resource id, you MUST reuse it in later requests that need those values (and re-test ops that failed for missing auth).
18. ❌ **Hammering a slowing server** — If latency rises, timeouts appear, or you get 429/5xx overload signals, insert/increase `sleep` between requests (2s → 5s → 10s → 15s). Do not stop; pace and continue.
19. ❌ **Exceeding DoS budget** — Never send 50+ aliases, huge batches, or `first: 9999`. Stay within the budget table; abort further DoS checks on overload.
20. ❌ **Missing `attack_chain` on chained findings** — Token/id harvest → exploit steps must be listed.
21. ❌ **Duplicate vulns from re-tests** — Dedup by title + affected_operation + root cause; enrich evidence instead of cloning entries.
22. ❌ **Only testing top-level authorization** — The #1 GraphQL finding is NESTED/field-level auth (e.g. `order.customer.paymentMethods`). Walk the graph field-by-field per role (Check 41), not just direct object access.
23. ❌ **Calling auth bypass on an error body** — A `200` with `"Not authorized"` in the body is enforced. Read the body, not the status.
24. ❌ **Skipping IDE exposure / engine fingerprint** — Check GraphiQL/Playground/Voyager on the host (Check 45), fingerprint the engine (Check 22), and note known CVEs for the version.
25. ❌ **Testing subscriptions only over HTTP** — Use the real WebSocket transport (graphql-ws / graphql-transport-ws); test no/expired/other-user token and cross-site (Origin) hijacking.
26. ❌ **Assuming introspection-off = no schema** — Try introspection-bypass variants and Clairvoyance-style suggestion fuzzing to reconstruct the schema.
27. ❌ **Not saving the report to a file** — The scan MUST auto-write `{workspace}/graphql_scans/{full_hostname}.json` and verify it exists (Phase 5). Printing JSON in chat is not saving. Never finish without a confirmed saved file; retry with a fallback path if the first write fails.
