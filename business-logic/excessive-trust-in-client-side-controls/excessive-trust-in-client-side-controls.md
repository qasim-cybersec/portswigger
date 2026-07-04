# Excessive trust in client-side controls

**Category:** Business Logic Vulnerability
**Difficulty:** ⭐ (Apprentice)
**Severity:** 🟠 High
**OWASP Top 10:** A04:2021 – Insecure Design

---

## Description

The application calculates the cost of a purchase using a `price` value that is submitted by the client in the add-to-cart request, rather than looking the price up server-side from its own product catalog. Because the server trusts this attacker-controlled field, a user can set an arbitrary price for any item and buy high-value goods for a fraction of their real cost. Here, a $1337.00 leather jacket — normally unaffordable with the account's $100.00 store credit — was purchased for $0.01 per unit.

---

## Discovery Process

### Step 1 — Log in and review available funds

Logged in to the application as the low-privileged user `wiener`. The account page confirmed a store credit balance of **$100.00**, which sets the ceiling on what can normally be purchased.

> 📸 `screenshots/01-my-account.png`

### Step 2 — Identify an unaffordable target product

The target item, the *Lightweight "l33t" Leather Jacket*, is priced at **$1337.00** — far above the $100.00 store credit. Attempting to buy it through the normal flow is impossible because the total exceeds the available balance, so any successful purchase must involve manipulating the amount the server charges.

### Step 3 — Inspect the add-to-cart request

The jacket was added to the basket while proxying traffic through Burp Suite. The resulting `POST /cart` request revealed that the product's **price is submitted from the client** as a form parameter (`price`), populated from a hidden field on the product page. This is the tell-tale sign of excessive trust in client-side controls: a security- and finance-relevant value is being taken from the browser instead of being enforced on the server.

---

## Exploitation

### Step 4 — Tamper the price parameter

The `POST /cart` request was sent to Burp Repeater and the `price` parameter was changed to `1` (one cent). The body submitted was `productId=1&redir=PRODUCT&quantity=1&price=1`. The server responded with `HTTP/2 302 Found`, redirecting back to the product page and silently accepting the manipulated price — confirming it never re-validated the amount against its own catalog.

**Request sent:**

```http
POST /cart HTTP/2
Host: 0abd00c504534b7482d7203500b70036.web-security-academy.net
Cookie: session=Waysolfdm BKVxVZRZ2TyfLZerfuw0lxo
Content-Length: 44
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Origin: https://0abd00c504534b7482d7203500b70036.web-security-academy.net
Referer: https://0abd00c504534b7482d7203500b70036.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1

productId=1&redir=PRODUCT&quantity=1&price=1
```

**Response received:**

```http
HTTP/2 302 Found
Location: /product?productId=1
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

> 📸 `screenshots/02-cart-price-tampered.png`

### Step 5 — Place the order and solve the lab

With the tampered line item in the basket (2 units at the manipulated price), the order was placed. The checkout succeeded for a **total of $0.02**, deducting only two cents from the store credit (balance dropped from $100.00 to $99.98). The lab status changed to **Solved** with the "Congratulations, you solved the lab!" banner, and the order confirmation displayed the $1337.00 jacket purchased at the attacker-defined price.

> 📸 `screenshots/03-solved.png`

---

## Impact

- **Arbitrary price manipulation** — an attacker can set any price on any product, purchasing goods of any value for effectively nothing.
- **Direct financial loss to the merchant** — every order placed this way represents lost revenue equal to the difference between the real price and the forged one.
- **Bypass of spending limits and store credit** — items whose real cost exceeds the buyer's available funds become freely purchasable, defeating the intended affordability constraint.
- **Scalable, automatable fraud** — the tampered request is trivial to script and replay across the entire catalog, so the abuse is not limited to a single high-value item.

---

## Root Cause

The server derives the amount to charge from a `price` field supplied in the client's HTTP request instead of retrieving the authoritative price from its own database using the `productId`. Client-submitted values are fully attacker-controlled, so any trust placed in them is misplaced. The pricing decision — a core business-logic invariant — is effectively delegated to the browser, and no server-side check reconciles the submitted price against the real one.

**Vulnerable flow:**

```text
Client submits productId=1 & price=1 → Server stores 1¢ as the line price
   → Checkout totals the client-supplied prices
   → ❌ No server-side lookup of the real catalog price → order accepted at 1¢
```

**Secure flow:**

```text
Client submits productId=1 only → Server looks up price from its own catalog
   → Checkout totals server-authoritative prices
   → ✅ Client-supplied price is ignored/rejected → order charged the real $1337.00
```

---

## Remediation

- **Never trust client-supplied prices** — remove `price` (and any other cost-bearing field) from client-submitted forms and resolve it server-side from the product ID.
- **Enforce pricing authoritatively on the server** — compute every line total and order total from the trusted catalog at checkout, and reject or recompute any price value present in the request.
- **Validate the order server-side before payment** — confirm the charged total matches the recomputed catalog total and that the buyer's balance covers the real amount.
- **Treat all client input as untrusted** — apply the same principle to quantity, discounts, and shipping so business-logic constraints cannot be overridden from the browser.

---

## Tools Used

- Burp Suite (Proxy & Repeater)

---

## References

- <https://portswigger.net/web-security/logic-flaws>
- <https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls>
- <https://owasp.org/Top10/A04_2021-Insecure_Design/>
