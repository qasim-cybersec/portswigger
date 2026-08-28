# Username enumeration via different responses

**Category:** Broken Authentication  
**Difficulty:** ⭐ (Apprentice)  
**Severity:** 🟠 High  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

The login form discloses whether a submitted username exists in the system through distinct error messages. An attacker can exploit this behavioral discrepancy to enumerate valid usernames, then perform a targeted brute-force attack against the confirmed account to gain unauthorized access.

---

## Discovery Process

**Step 1 — Initial login probe with non-existent username**

A login attempt was submitted with a random username. The server responded with the error message **"Invalid username"**, indicating that the application explicitly differentiates between non-existent and existing usernames.

> 📸 `screenshots/01-invalid-username.png`

**Step 2 — Username enumeration with ffuf**

A wordlist-based fuzzing attack was launched against the `username` parameter using `ffuf`. The tool was configured to send POST requests to the login endpoint with a static dummy password while iterating through a list of candidate usernames.

> 📸 `screenshots/02-ffuf-username-command.png`

**Step 3 — Identifying the valid username from response discrepancies**

The `ffuf` output revealed that the candidate `app01` produced a response with a **body size of 3246 bytes**, whereas all other usernames returned **3244 bytes**. This consistent delta in response length confirmed that `app01` is a valid registered username, as the server rendered a different error page ("Incorrect password" instead of "Invalid username").

> 📸 `screenshots/03-ffuf-username-results.png`

**Step 4 — Confirming valid username manually**

To verify the `ffuf` finding, the username `app01` was submitted with an arbitrary password. The server responded with **"Incorrect password"**, definitively confirming that the account exists.

> 📸 `screenshots/04-test-valid-username.png`  
> 📸 `screenshots/05-incorrect-password.png`

---

## Exploitation

**Step 5 — Password brute-force with ffuf**

With the valid username `app01` confirmed, a second `ffuf` attack was configured to brute-force the `password` parameter. The username was held constant while the tool iterated through a password wordlist.

> 📸 `screenshots/06-ffuf-password-command.png`

**Step 6 — Identifying the correct password**

The `ffuf` results showed that the password `sunshine` caused the server to return an **HTTP 302 Found** redirect with a response body size of **0 bytes**. This behavior diverged sharply from all other candidates, which returned HTTP 200 with a body size of 3246 bytes. The 302 status indicated a successful authentication and a redirect to the user's account dashboard.

> 📸 `screenshots/07-ffuf-password-results.png`

**Step 7 — Account access and lab completion**

Logging in with `app01:sunshine` granted full access to the victim's account. The "My Account" page loaded successfully, displaying the user's email address (`app01@normal-user.net`) and triggering the lab's solved state.

> 📸 `screenshots/08-lab-solved.png`

---

## Impact

- **Account Takeover** — An attacker can discover valid usernames and brute-force their passwords, leading to complete compromise of user accounts.
- **Credential Stuffing Amplification** — Username enumeration allows attackers to prune their credential lists to only confirmed accounts, dramatically increasing the efficiency of stuffing attacks.
- **User Privacy Violation** — The ability to verify whether a specific username exists in the system leaks sensitive user enrollment data and can facilitate targeted phishing or social engineering campaigns.

---

## Root Cause

The application performs two sequential validation checks during login: first verifying the username, then verifying the password. Instead of returning a single generic error for all authentication failures, it emits distinct error strings (`"Invalid username"` vs `"Incorrect password"`) and slightly different response sizes depending on which check fails.

**Vulnerable flow:**

```
Attacker submits username → Server checks username DB → Username not found → ❌ Returns "Invalid username" (size: 3244)
Attacker submits username → Server checks username DB → Username found → Checks password → Wrong password → ❌ Returns "Incorrect password" (size: 3246)
```

**Secure flow:**

```
Attacker submits username → Server checks username DB → [Any failure] → ✅ Returns generic "Invalid username or password" (identical size & status for all failures)
```

---

## Remediation

- **Generic Error Messages** — Return a single, identical error message (e.g., "Invalid username or password") for every failed login attempt, regardless of whether the username or password was incorrect.
- **Consistent Response Profiles** — Ensure that failed login responses have identical HTTP status codes, body sizes, and rendering times to prevent side-channel enumeration via response length or timing analysis.
- **Rate Limiting & Account Lockout** — Implement progressive delays, CAPTCHA challenges, or temporary account lockouts after a threshold of failed attempts to impede automated brute-force and enumeration attacks.

---

## Tools Used

- ffuf (Fast web fuzzer)
- Web browser

---

## References

- [PortSwigger – Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)
- [OWASP – Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
