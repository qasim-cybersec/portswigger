# JWT authentication bypass via algorithm confusion with no exposed key

**Category:** Broken Authentication (JWT)
**Difficulty:** ⭐⭐⭐ (Expert)
**Severity:** 🔴 Critical
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

This lab uses JWT-based authentication with tokens signed using RS256 (asymmetric). Unlike a standard algorithm-confusion scenario, the server's RSA public key is **not** exposed via a `/jwks.json` endpoint or any other public artifact. However, because the server accepts either RS256 or HS256 depending on the attacker-controlled `alg` header, it is still possible to recover a valid RSA public key by analyzing two RSA-signed tokens issued by the server and deriving candidate moduli mathematically. Once a valid public key is recovered, it can be reused as an HMAC secret to forge an administrator token, exactly as in the standard algorithm-confusion attack.

The key difference from the standard lab is that the public key is not published, yet it can still be recovered from signatures alone.

---

## Discovery Process

### Step 1 — Login with the supplied credentials

Logged in to the application as the low-privileged user `wiener`. This issued a session JWT signed with RS256 that was sent with subsequent requests.

> 📸 `screenshots/01-login.png`

### Step 2 — Confirm the admin restriction and inspect the token

Sent `GET /admin` with the RS256-signed session cookie in Burp Repeater. The server returned `HTTP/2 401 Unauthorized`, confirming that the admin interface was restricted. Unlike the standard variant of this lab, no `/jwks.json` or equivalent JWK Set endpoint was exposed, so the RSA public key could not simply be downloaded.

> 📸 `screenshots/02-admin-401.png`

---

## Exploitation

### Step 3 — Obtain a second RSA-signed token

The `sig2n` technique requires two distinct valid signature/message pairs generated with the same RSA key. To obtain a second token signed with the same server key, the session was logged out and logged back in as `wiener`, issuing a fresh RS256-signed JWT.

### Step 4 — Recover the public key modulus using sig2n

The two RS256-signed JWTs were fed into the `sig2n` tool (`portswigger/sig2n` Docker image), which implements a GCD-based key-recovery technique: given two valid signature/message pairs produced with the same RSA key, candidate values of the modulus `n` can be derived without ever seeing the key itself.

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

The tool ran `jwt_forgery.py` internally and returned multiple **candidate moduli** (multiplier 1, multiplier 2, …), each exported as a Base64-encoded x509 key and PKCS1 key, along with a pre-forged **tampered JWT** for each candidate — already re-signed with HS256 using that candidate key as the HMAC secret, and with the payload's `sub` claim changed.

> 📸 `screenshots/03-sig2n-bruteforce.png`

### Step 5 — Validate the correct candidate key

Because multiple candidate keys are produced, the correct one has to be identified. One of the tampered JWTs was placed in the session cookie and sent against a low-privilege, non-destructive endpoint (`GET /my-account?id=wiener`) to check whether the server accepted the forged signature.

**Request sent:**

```http
GET /my-account?id=wiener HTTP/2
Host: 0a42004d0457abb2808499l2002200al.web-security-academy.net
Cookie: session=<tampered-jwt-candidate>
```

**Response received:**

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3528
```

The `200 OK` response confirmed this candidate modulus was the correct one — the server accepted an HS256-signed token whose secret was derived purely from analyzing two RS256 signatures.

> 📸 `screenshots/04-my-account-tampered-200.png`

### Step 6 — Build a symmetric key from the recovered modulus

Using the Burp JWT Editor extension, a symmetric key was created manually, setting `kty: oct` and pasting the Base64-encoded key value (`k`) recovered by sig2n for the validated candidate, matching the original token's `kid`.

> 📸 `screenshots/05-symmetric-key-created.png`

### Step 7 — Forge an admin token and delete `carlos`

The `/admin/delete` request was sent to Repeater. In the JWT tab the header `alg` was set to `HS256` and the payload `sub` was changed to `administrator`, then signed with the symmetric key built in Step 5.

**Request sent:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a42004d0457abb2808499l2002200al.web-security-academy.net
Cookie: session=<forged-hs256-admin-jwt>
```

**Response received:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

The `302 Found` response confirmed the forged administrator token was accepted and the delete action succeeded.

> 📸 `screenshots/06-delete-carlos-302.png`

### Step 8 — Lab solved

The lab status changed to **Solved** with the "Congratulations, you solved the lab!" banner.

> 📸 `screenshots/07-solved.png`

---

## Impact

- **Full authentication bypass without any key disclosure** — an attacker does not need a public JWKS endpoint; two ordinary RS256-signed tokens from any authenticated session are enough to mathematically recover a usable public key.
- **Privilege escalation to administrator** — the recovered key allows forging tokens with an arbitrary `sub` claim, including `administrator`.
- **Destructive account actions** — admin access allowed deletion of the user `carlos`; any account could similarly be deleted, modified, or impersonated.
- **Broader blast radius than the standard algorithm-confusion bug** — because no public key needs to be exposed for this attack to work, "not publishing JWKS" is not a sufficient mitigation on its own.

---

## Root Cause

As with standard algorithm confusion, the server selects the verification routine based on the attacker-controlled `alg` header rather than pinning the expected algorithm, and reuses the same RSA public key material as an HMAC secret when `alg` is HS256. The additional weakness here is architectural: RSA public keys are not secret by design, and two valid signatures produced with the same key are mathematically sufficient to reconstruct candidate values of the modulus — so failing to publish the key does not prevent recovery.

**Vulnerable flow:**

```text
Attacker collects 2 RS256-signed tokens → derives candidate n via GCD (sig2n)
   → converts recovered key to HMAC secret → signs alg=HS256 token
   → ❌ Server verifies with the same key regardless of alg → forged token accepted
```

**Secure flow:**

```text
Attacker collects 2 RS256-signed tokens → derives candidate n via GCD (sig2n)
   → signs alg=HS256 token with recovered key as HMAC secret
   → ✅ Server ignores token's alg, enforces RS256 verification only → forged token rejected
```

---

## Remediation

- **Pin the verification algorithm** — explicitly configure the expected algorithm (RS256) server-side and reject tokens whose `alg` header doesn't match, instead of trusting attacker-supplied input.
- **Use separate keys per algorithm class** — never allow an RSA key (public or private) to also be usable as an HMAC secret; keep symmetric and asymmetric key material strictly distinct in the verification library.
- **Restrict signature exposure** — minimize the number of tokens signed with the same long-lived key that an attacker can collect, and rotate keys regularly to shrink the window for key-recovery attacks.
- **Maintain a strict algorithm allow-list** — reject `none` and any unexpected `alg` value in the JWT library configuration.

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- Burp JWT Editor Extension
- sig2n (`portswigger/sig2n` Docker image, `jwt_forgery.py`)

---

## References

- <https://portswigger.net/web-security/jwt/algorithm-confusion>
- <https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key>
- RFC 7519 – JSON Web Token (JWT)
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>
