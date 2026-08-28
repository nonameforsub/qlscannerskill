## Appendix E: Skill-File Ablation Detail
The table below reports the full per-vulnerability results of the skill-file ablation described in Section 6 of the main manuscript. The *With skill* columns show the complete QLScanner; the *Without skill* columns show the same agent and model given only the endpoint and an instruction to test it without the skill file, on the anonymized application. Reachability follows Table 1 of the main text.

**Note:** *With skill* is the full QLScanner; *without skill* is the same agent and model given only the endpoint and an instruction to test it. ✓ indicates a detection reproduced, ✗ indicates a false negative, and N/A indicates a vulnerability not reachable in that mode by construction. Superscripts on OS Command Injection give the number of the two injectable sinks recovered. ‡ Expert mode denies the schema field only; the schema was recovered by type probing and field-suggestion inference. Fingerprinting is reconnaissance and excluded from recall.

| Vulnerability | With skill (Beg.) | With skill (Exp.) | Without skill (Beg.) | Without skill (Exp.) |
| :--- | :---: | :---: | :---: | :---: |
| **Reconnaissance** *(not counted in recall)* | | | | |
| Fingerprinting GraphQL | ✓ | ✓ | ✗ | ✗ |
| **Denial of Service** | | | | |
| Batch Query Attack | ✓ | ✓ | ✓ | ✗ |
| Deep Recursion Query | ✓ | N/A | ✓ | N/A |
| Resource-Intensive Query | ✓ | ✓ | ✓ | ✓ |
| Field Duplication | ✗ | ✓ | ✗ | ✓ |
| Aliases-based Attack | ✓ | ✓ | ✓ | ✓ |
| Circular Fragment | ✓ | ✗ | ✗ | ✗ |
| **Information Disclosure** | | | | |
| Introspection | ✓ | N/A‡ | ✓ | N/A‡ |
| GraphiQL Interface | ✓ | N/A | ✗ | N/A |
| Field Suggestions | ✗ | ✗ | ✓ | ✓ |
| Server-Side Request Forgery | ✓ | ✓ | ✓ | ✓ |
| Stack Trace Errors | ✗ | ✓ | ✗ | ✗ |
| **Code Execution** | | | | |
| OS Command Injection #1,#2 | 1/2 | 1/2 | 1/2 | 1/2 |
| **Injection** | | | | |
| Stored XSS | ✓ | ✓ | ✓ | ✗ |
| Log Injection | ✗ | N/A | ✗ | N/A |
| HTML Injection | ✓ | ✓ | ✓ | ✗ |
| SQL Injection | ✓ | ✓ | ✗ | ✗ |
| **Authorization Bypass** | | | | |
| GraphiQL Protection Bypass | ✓ | N/A | ✗ | N/A |
| Query Deny-List Bypass | N/A | ✓ | N/A | ✗ |
| JWT Token Forge | ✓ | ✓ | ✓ | ✗ |
| **Miscellaneous** | | | | |
| Path Traversal / File Write | ✓ | ✗ | ✓ | ✗ |
| Weak Password Protection | ✓ | ✓ | ✓ | ✓ |
| **Summary** | | | | |
| Vulnerabilities found | 16/21 | 13/17 | 13/21 | 7/17 |
| Recall | 76.2% | 76.5% | 61.9% | 41.2% |



## Appendix H: Per-Vulnerability Run-to-Run Variance

The table below reports the full per-vulnerability results of the four repeated runs summarized in Section 5.2. Ten of the 21 reachable vulnerabilities were detected in every run and nine intermittently. Reachability follows Table 1.

**Note:** ✓ indicates a detection reproduced, ✗ indicates a false negative. § indicates the vulnerability was found inside sessino file.

| DVGA Vulnerability | R1 | R2 | R3 | R4 | Hits |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Detected in every run** | | | | | |
| Batch Query Attack | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Aliases-based Attack | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Introspection | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Field Suggestions | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Server-Side Request Forgery | ✓ | ✓ | ✓ | ✓ | 4/4 |
| OS Command Injection #1 | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Stored XSS | ✓ | ✓ | ✓ | ✓ | 4/4 |
| HTML Injection | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Path Traversal / File Write | ✓ | ✓ | ✓ | ✓ | 4/4 |
| Weak Password Protection | ✓ | ✓ | ✓ | ✓ | 4/4 |
| **Detected intermittently** | | | | | |
| Deep Recursion Query | ✓ | ✗ | ✓ | ✓§ | 3/4 |
| Resource-Intensive Query | ✗ | ✓§ | ✓ | ✓ | 3/4 |
| Field Duplication | ✓ | ✓ | ✓ | ✗ | 3/4 |
| Log Injection | ✓ | ✓ | ✓ | ✗ | 3/4 |
| Circular Fragment | ✓§ | ✓§ | ✗ | ✓§ | 3/4 |
| Stack Trace Errors | ✓ | ✗ | ✓ | ✓ | 3/4 |
| JWT Token Forge | ✓ | ✓ | ✓ | ✗ | 3/4 |
| GraphiQL Interface | ✓ | ✓ | ✗ | ✗ | 2/4 |
| OS Command Injection #2 | ✗ | ✗ | ✓ | ✗ | 1/4 |
| **Detected in no run** | | | | | |
| SQL Injection | ✗ | ✗ | ✗ | ✗ | 0/4 |
| GraphiQL Protection Bypass | ✗ | ✗ | ✗ | ✗ | 0/4 |
| **Summary** | | | | | |
| **Vulnerabilities found** | 17/21 | 16/21 | 17/21 | 14/21 | |
| **Recall** | 81.0% | 76.2% | 81.0% | 66.7% | |

## Appendix I: Full Per-Vulnerability Detection Matrix

The table below presents the complete, per-vulnerability detection matrix for the Damn Vulnerable GraphQL Application (DVGA). It details the successes and false negatives for GraphQLer, PrediQL, and QLScanner across all 22 documented vulnerabilities in both Beginner and Expert modes.

**Note:** ✓ indicates a detection reproduced, ✗ indicates a false negative, N/A indicates a vulnerability not exploitable in that mode by construction, and N/R indicates a tool produced no result because it could not execute. Expert mode neutralizes seven vulnerabilities and introduces one (the query deny list) that is absent from Beginner mode, so recall is computed over 21 and 17 reachable vulnerabilities. QLScanner uses 3.2× fewer LLM calls and 3.1× fewer HTTP requests than PrediQL at 3.6× lower wall-clock time, at the cost of higher token volume per call. In the resource rows, N/A marks a metric that does not apply to a non-LLM tool and — marks a figure we did not record. 
* Superscripts on OS Command Injection give the number of the two injectable sinks recovered. 
* ‡ Expert mode denies the `__schema` field only; our agent recovered the schema through `__type` probing, falling back to field-suggestion inference too, which is what enabled the remaining Expert-mode checks. 
* Fingerprinting is listed by DVGA under *Reconnaissance* rather than as an injected flaw and is excluded from recall. 
* † PrediQL failed to run in expert mode because introspection was not enabled.

| DVGA Vulnerability | GraphQLer (Beg.) | PrediQL GPT-5-mini (Beg.) | PrediQL MiniMax (Beg.) | QLScanner (Beg.) | GraphQLer (Exp.) | PrediQL (Exp.) | QLScanner (Exp.) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Reconnaissance** *(methodology; not counted in recall)* | | | | | | | |
| Fingerprinting GraphQL | ✗ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| **Denial of Service** | | | | | | | |
| Batch Query Attack | ✗ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| Deep Recursion Query | ✗ | ✗ | ✗ | ✓ | N/A | N/A | N/A |
| Resource-Intensive Query | ✗ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| Field Duplication | ✗ | ✗ | ✗ | ✗ | ✗ | N/R | ✓ |
| Aliases-based Attack | ✗ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| Circular Fragment | ✗ | ✗ | ✗ | ✓§ | ✗ | N/R | ✓ |
| **Information Disclosure** | | | | | | | |
| Introspection | ✓ | ✓ | ✓ | ✓ | N/A | N/A | N/A‡ |
| GraphiQL Interface | ✗ | ✗ | ✗ | ✗ | N/A | N/A | N/A |
| Field Suggestions | ✓ | ✓ | ✓ | ✓ | ✗ | N/R | ✓ |
| Server-Side Request Forgery | ✓ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| Stack Trace Errors | ✗ | ✗ | ✗ | ✗ | ✗ | N/R | ✓ |
| **Code Execution** | | | | | | | |
| OS Command Injection #1, #2 | 1/2 | 2/2 | 1/2 | 2/2 | 0/2 | N/R | 1/2 |
| **Injection** | | | | | | | |
| Stored XSS | ✓ | ✓ | ✓ | ✓ | ✗ | N/R | ✓ |
| Log Injection | ✗ | ✗ | ✗ | ✓ | N/A | N/A | N/A |
| HTML Injection | ✗ | ✓ | ✓ | ✗ | ✗ | N/R | ✗ |
| SQL Injection | ✓ | ✓ | ✗ | ✓ | ✗ | N/R | ✗ |
| **Authorization Bypass** | | | | | | | |
| GraphiQL Protection Bypass | ✗ | ✗ | ✗ | ✗ | N/A | N/A | N/A |
| Query Deny-List Bypass | N/A | N/A | N/A | N/A | ✓ | N/R | ✗ |
| JWT Token Forge | ✗ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| **Miscellaneous** | | | | | | | |
| Path Traversal / File Write | ✓ | ✓ | ✓ | ✓ | ✗ | N/R | ✓ |
| Weak Password Protection | ✗ | ✗ | ✗ | ✓ | ✗ | N/R | ✓ |
| **Summary** | | | | | | | |
| **Vulnerabilities found** | 7/21 | 8/21 | 6/21 | **16/21** | 1/17 | ---† | **13/17** |
| **Recall** | 33.3% | 38.1% | 28.6% | **76.2%** | 5.9% | ---† | **76.5%** |
| **Performance Metrics** | | | | | | | |
| Wall-clock time | 3,086 s | 4,777 s | 2,770 s | **768 s** | 1,367 s | N/R | **537 s** |
| LLM calls | N/A | 218 | 205 | **68** | N/A | N/R | **77** |
| HTTP requests | — | 706 | 847 | **226** | — | N/R | **215** |
| Tokens | N/A | 504 K | — | 4.00 M | N/A | N/R | 4.56 M |


## Appendix L: Per-Vulnerability Recall Across Backbone Models

The table below reports the full per-vulnerability results of the four-model sweep summarized in Section 5.2 of the main manuscript. Reachability follows Table 1.

**Note:** ✓ indicates a detection reproduced, ✗ indicates a false negative, and N/A indicates a vulnerability not exploitable in that mode. Recall is computed over 21 reachable vulnerabilities in Beginner mode and 17 in Expert mode. Each configuration ran against a separate DVGA instance on its own hostname, reset before the run, so no configuration observed state left by another.
* § Detected only under an authenticated session.
* ¶ Field suggestions were used during enumeration but not reported as a finding.
* ‡ Introspection is blocked in Expert mode; every configuration nonetheless recovered the schema, via `__type` probing and field-suggestion inference, which is what enabled the remaining Expert-mode checks.

| DVGA Vulnerability | GLM-4.7 (Beg.) | GLM-5.2 (Beg.) | M2.7 (Beg.) | M3 (Beg.) | GLM-4.7 (Exp.) | GLM-5.2 (Exp.) | M2.7 (Exp.) | M3 (Exp.) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Reconnaissance** *(not counted in recall)* | | | | | | | | |
| Fingerprinting GraphQL | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Denial of Service** | | | | | | | | |
| Batch Query Attack | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Deep Recursion Query | ✓§ | ✓ | ✓ | ✓ | N/A | N/A | N/A | N/A |
| Resource-Intensive Query | ✗ | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✓ |
| Field Duplication | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Aliases-based Attack | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Circular Fragment | ✓§ | ✓§ | ✓§ | ✓§ | ✗ | ✗ | ✓§ | ✓ |
| **Information Disclosure** | | | | | | | | |
| Introspection | ✓ | ✓ | ✓ | ✓ | N/A‡ | N/A‡ | N/A‡ | N/A‡ |
| GraphiQL Interface | ✗ | ✗ | ✓ | ✗ | N/A | N/A | N/A | N/A |
| Field Suggestions | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗¶ | ✓ |
| Server-Side Request Forgery | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Stack Trace Errors | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ |
| **Code Execution** | | | | | | | | |
| OS Command Injection #1, #2 | 0/2 | 2/2 | 1/2 | 2/2 | 1/2 | 1/2 | 0/2 | 1/2 |
| **Injection** | | | | | | | | |
| Stored XSS | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Log Injection | ✗ | ✗ | ✓ | ✓ | N/A | N/A | N/A | N/A |
| HTML Injection | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ | ✓ | ✗ |
| SQL Injection | ✗ | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| **Authorization Bypass** | | | | | | | | |
| GraphiQL Protection Bypass | ✗ | ✗ | ✗ | ✗ | N/A | N/A | N/A | N/A |
| Query Deny-List Bypass | N/A | N/A | N/A | N/A | ✗ | ✗ | ✗ | ✗ |
| JWT Token Forge | ✗ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| **Miscellaneous** | | | | | | | | |
| Path Traversal / File Write | ✗ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Weak Password Protection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ |
| **Summary** | | | | | | | | |
| **Vulnerabilities found** | 10/21 | 16/21 | **17/21** | 16/21 | 5/17 | 10/17 | 10/17 | **13/17** |
| **Recall** | 47.6% | 76.2% | **81.0%** | 76.2% | 29.4% | 58.8% | 58.8% | **76.5%** |