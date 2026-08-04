# 2FA broken logic

**Category:** Broken Authentication
**Difficulty:** ⭐ (Apprentice)
**Severity:** 🔴 Critical
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

The application implements a two-step login flow: username/password, followed by a 4-digit MFA code sent to the account owner. The identity being verified in the second step is tracked using a plain, client-supplied cookie (`verify`) rather than being bound server-side to the session created after step one. Because this cookie can be freely rewritten, an attacker who owns a valid low-privileged account can redirect the MFA check onto a victim account, and — since the MFA endpoint applies no rate-limiting or lockout — brute-force the victim's 4-digit code to complete a full account takeover.

---

## Discovery Process

### Step 1 — Log in with valid low-privileged credentials

Logged in to the application as `wiener` using valid credentials. Submitting the login form redirected to `/login2`, which prompts for the second-factor verification code.

> 📸 `screenshots/01-login-page.png`

### Step 2 — Inspect the /login2 request in Burp

Proxied the traffic through Burp Suite and examined the `GET /login2` request. Alongside the `session` cookie, a second cookie — `verify=wiener` — was present. This cookie determines which account's identity is currently pending MFA verification. Critically, it is a plain, unsigned value that the browser controls, not something cryptographically tied to the authenticated session.

> 📸 `screenshots/02-login2-request-wiener.png`

### Step 3 — Tamper the verify cookie to target another user

Changed the `verify` cookie from `wiener` to `carlos` (a known username on the platform) while keeping the same `session` cookie, and resent the `GET /login2` request. The server responded `HTTP/2 200 OK` and rendered the identical MFA verification page — now scoped to `carlos` — without checking that the requested verify target matched the identity that had actually authenticated in step 1.

> 📸 `screenshots/03-login2-request-carlos.png`

This confirms the vulnerability: the server trusts the client-supplied `verify` cookie to decide whose account the next MFA code will be checked against, instead of deriving that identity from the session established at login.

---

## Exploitation

### Step 4 — Brute-force the victim's MFA code

With `verify=carlos` set, the only remaining barrier was guessing the correct 4-digit MFA code. The endpoint applies no rate-limiting or lockout on failed attempts, making this fully automatable. Used `ffuf` to POST every 4-digit value (`0000`–`9999`) as the `mfa-code` parameter against `/login2`, with the `verify=carlos` cookie attached.

**Command used:**

```bash
ffuf -u "https://0ad400660387bded80d96cb00003003a.web-security-academy.net/login2" \
  -X POST \
  -H "Cookie: verify=carlos; session=mQEwqolFHhMOl7W8Qd8AVVdu81Wqj5iJ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "mfa-code=FUZZ" \
  -w <(seq -f "%04g" 0 9999) \
  -o results.json -of json
```

> 📸 `/screenshots04-ffuf-brute-force.png`

### Step 5 — Identify the valid code and gain access

Filtering the `ffuf` results by response length/status isolated the single code that produced a different (successful) response from the ~9,999 failed guesses. Submitting that code completed the login flow as `carlos`.

### Step 6 — Confirm account takeover

The **My Account** page confirmed the session now belonged to `carlos` ("Your username is: carlos"), and the lab banner displayed **Solved**.

> 📸 `screenshots/05-solved-carlos-account.png`

---

## Impact

- **Full account takeover of any user** — an attacker who controls any single valid low-privileged account can redirect the MFA check to an arbitrary victim by username alone, with no knowledge of the victim's password.
- **2FA provides no real protection** — since the code space is only 10,000 possibilities with no lockout, the second factor is trivially defeated by an automated, unattended attack.
- **Scalable across the user base** — if usernames are enumerable or previously leaked (e.g. from a breach), this becomes a repeatable account-takeover vector for every account on the platform, not just a single target.
- **Undermines the security guarantee MFA is meant to provide** — decoupling "who authenticated in step 1" from "whose code is being checked in step 2" defeats the entire purpose of a second factor.

---

## Root Cause

The server tracks which account's MFA code is currently being verified using a plain, attacker-writable cookie (`verify`) instead of deriving that identity strictly from the already-authenticated session established in step one of login. Combined with the absence of rate-limiting on the MFA submission endpoint, this lets an attacker (a) redirect the verification target to any username simply by editing a cookie, and (b) exhaustively brute-force the 4-digit code space with no penalty for failed attempts.

**Vulnerable flow:**

```text
Client logs in as wiener (valid creds) → Server sets verify=wiener cookie
   → Client rewrites cookie to verify=carlos → Server accepts, serves carlos's MFA prompt
   → ❌ No binding between session identity and verify target
   → Client brute-forces mfa-code with no rate limit → correct code found → logged in as carlos
```

**Secure flow:**

```text
Client logs in as wiener (valid creds) → Server binds "pending MFA for wiener" to the session server-side
   → Client cannot alter which account's MFA is being checked
   → Server enforces rate-limiting/lockout on mfa-code attempts
   → ✅ Both identity-swap and brute-force are blocked
```

---

## Remediation

- **Bind MFA verification identity to the server-side session** — never trust a client-supplied cookie or parameter to determine which account's second factor is being checked; store the pending-verification identity server-side against the authenticated session token.
- **Rate-limit and lock out MFA attempts** — after a small number of failed codes, temporarily lock the account or force re-authentication from step one, making brute-force infeasible.
- **Use a sufficiently large, expiring, single-use code** — increase code length/entropy and enforce a short expiry window so guessing remains impractical even if rate-limiting is imperfect.
- **Log and alert on verify-target mismatches** — flag any case where the requested MFA verification target diverges from the identity that completed step one, since this pattern is itself a strong tampering signal.

---

## Tools Used

- Burp Suite (Proxy)
- ffuf

---

## References

- <https://portswigger.net/web-security/authentication/multi-factor>
- <https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic>
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>