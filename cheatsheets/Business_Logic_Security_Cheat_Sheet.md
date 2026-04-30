# Business Logic Security Cheat Sheet

## Introduction

Business logic vulnerabilities are flaws in the way an application implements its intended workflow. They aren't missing input sanitization or unescaped output. The code does what the developer told it to do, but what the developer told it to do doesn't match what the business actually needs. A user skips a required step, submits a request out of order, pays a negative price, stacks coupons in a way nobody planned for, or wins a race against the server's own bookkeeping.

No scanner will find these bugs for you. They don't have a signature to match on. They show up in code that looks perfectly fine in isolation because the bug isn't in any single function. It's in the gap between what the developer assumed and what a user can actually do.

This cheat sheet covers practical patterns for preventing business logic abuse. It's aimed at developers building features, not at penetration testers looking for them. For testing guidance, see the [OWASP Web Security Testing Guide, Business Logic Testing section](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).

Key takeaways:

- Always re-derive security-relevant values (prices, permissions, ownership) on the server. Client state is input, not truth.
- Enforce workflows as explicit state machines. Don't rely on the UI to gate the order of steps.
- Treat concurrency as a real threat. If two requests can race, assume they will.
- Rate-limit and monitor at the feature level, not just at authentication. Abuse-friendly features (referrals, coupons, password reset) need their own controls.
- Threat model from the business process, not just the technical architecture. Ask what happens if a user acts dishonestly, not just what happens if an attacker sends a malicious payload.

## Why Business Logic Flaws Are Different

Most well-known web vulnerabilities (SQL injection, XSS, CSRF, path traversal) have a clear technical signature. A security scanner can fuzz parameters, look for reflected payloads, and produce a reasonable report. Business logic bugs don't work that way.

Consider an e-commerce checkout. The server accepts a request containing a product ID, quantity, and coupon code. Every input is validated: the product ID exists, the quantity is a positive integer, the coupon code matches a known pattern. No technical rule is broken. But the application recalculates the total from the client-submitted price instead of looking it up server-side, so a user can pay one cent for a television. That's a business logic bug, and no amount of input validation helps, because the input is syntactically perfect.

The patterns repeat across industries:

- A user-facing application assumes the client will respect the order of steps in a multi-step workflow, and exposes the endpoints for each step without checking whether the previous steps were completed.
- A system takes user-controlled data (price, account balance, user role) from the request body and trusts it, because the UI never shows the user how to change it.
- An endpoint performs two operations (check balance, then debit) without a lock, so two concurrent requests both pass the balance check and both debit.
- A feature intended to reward legitimate use (referrals, points, promo credits) has no controls against one user creating many accounts.

None of these are subtle once you see them. They're just invisible to tools that don't understand the business process.

## Always Re-derive Security-relevant Values Server-side

The single most effective defensive habit is this: if a value in the request influences price, access, ownership, or state, assume the client made it up and recompute it from trusted data.

### Prices and Totals

Never accept a price, subtotal, tax, or total from the client. Accept product identifiers and quantities only, and compute the rest on the server from your own database. The same applies to discounts: accept a coupon code, validate the code server-side, and apply the discount server-side. Don't accept a "discount amount" field from the request.

| Client sends | Server should | Server should not |
|---|---|---|
| Product ID and quantity | Look up the price, compute line total | Accept a price field and trust it |
| Coupon code | Validate and apply the discount itself | Accept a "discounted total" field |
| Shipping selection | Compute cost from its own rate table | Accept a shipping cost field |
| Tax-exempt flag | Determine from account state | Accept a client-supplied exemption |

This pattern extends beyond commerce. A social app shouldn't accept a "post visibility" value from the client if the value is supposed to be derived from the user's privacy settings. A banking app shouldn't accept a "source account balance" that the client calculated.

### Permissions and Ownership

Re-check ownership on every request that acts on a resource. Don't rely on the URL, the referrer, or a flag in the request body. The backend should ask: "Is the authenticated user actually allowed to perform this action on this object, right now?"

A common mistake is checking ownership once when a resource is loaded and then trusting subsequent requests that reference it. Each request is independent. Each request must be authorized on its own.

### Identity and Role

Never accept a user ID, tenant ID, or role from the request body unless the request is explicitly an administrative action by a privileged caller, and even then the value has to be validated against what the caller is allowed to manage. The identity of the acting user always comes from the server-side session or token, never from a field the user can edit.

## Enforce Workflows as Explicit State Machines

Multi-step processes (signup flows, checkouts, approvals, KYC verification, password reset) are prime targets because developers often implement them as a sequence of pages that the UI walks the user through. If the UI is the only thing enforcing the sequence, an attacker who sends requests directly to each endpoint can skip steps, repeat steps, or reach terminal steps without the prerequisites.

### Model State on the Server

Every multi-step workflow should have an explicit state representation stored on the server, keyed to the user or session. Each transition should be validated against the current state.

A minimal pattern:

1. When the workflow starts, create a record with the initial state (e.g., `awaiting_email_verification`).
2. Each step endpoint checks the current state, performs the action, and updates the state to the next valid value.
3. If a request arrives for a step that doesn't match the current state, reject it.
4. Terminal actions (submit order, approve, transfer funds) only run if the state is exactly what's required for that action.

### Don't Use Hidden Form Fields as State

A pattern that shows up repeatedly in real applications is storing the "current step" as a hidden field in the form, or in a cookie the client can read. This is not enforcement. The client can set it to whatever value it wants. State lives on the server, in storage the client can't write to.

### Reject Replays of Completed Steps

Once a step has been completed, later attempts to re-run it should fail. This matters especially for one-time operations like applying a signup bonus, redeeming a coupon, claiming a voucher, or accepting a referral reward. The cleanest pattern is to mark each such operation complete in persistent storage and treat attempts to re-run it as errors.

### Expire Partial States

Workflows that pause for user input (email verification, bank transfer confirmation, multi-step KYC) should have a deadline. If the user hasn't progressed in some bounded time, invalidate the partial state and require them to start over. Long-lived half-completed workflows accumulate and are a frequent source of exploitable inconsistencies.

## Prevent Race Conditions on Sensitive Operations

Any operation that reads a value, makes a decision, and then writes a value is a potential race condition. If two requests can run at the same time, they can both read the old value, both decide the same thing, and both write. This is how loyalty points get drained, balances go negative, single-use coupons get redeemed many times, and one-per-account bonuses become many-per-account.

### Identify the Critical Sections

Ask which operations have the shape "check a condition, then act on it". Typical examples:

- Check balance, then debit.
- Check that a coupon hasn't been used, then record its use.
- Check that a user has fewer than N items, then add one.
- Check that a slot is available, then book it.
- Check that a referral code hasn't been applied to this account, then apply it.

Each of these is a race condition waiting to happen unless the check and the act are inside a single atomic operation.

### Use Database Transactions and Locks

The most broadly available fix is a database transaction with the right isolation level. At the default isolation level of most databases, the check and the update run separately and another transaction can slip between them. For operations that must be atomic, use one of:

- A `SERIALIZABLE` transaction isolation level. The database will detect conflicts and roll back one of the competing transactions.
- An explicit row lock (`SELECT ... FOR UPDATE` in PostgreSQL, MySQL InnoDB, and similar). The second caller blocks until the first one commits.
- A conditional update (`UPDATE ... WHERE balance >= amount`) that succeeds only if the predicate still holds at write time. Check the number of affected rows. If zero, the check failed and the caller should see an error.

### Use Idempotency Keys for External Actions

For operations that talk to external systems (charge a card, send money, issue a voucher), a retry from the client should not result in a duplicate action. Accept a client-supplied idempotency key, store it with the result, and return the cached result on retry. Stripe and other payment providers implement this pattern, and the same idea applies to any non-idempotent operation your own service exposes.

### Don't Assume "Fast Enough"

A common rationalization is "the window between the check and the update is microseconds, no attacker can exploit it". Concurrent request tools can trivially send dozens of requests to arrive within a millisecond of each other. Modern bug bounty tooling sends them as a single multiplexed HTTP/2 request so they land at the server effectively simultaneously. If the window exists at all, assume it's exploitable.

### Pattern Reference

| Operation shape | Safe pattern |
|---|---|
| Read-modify-write on a single row | `SELECT ... FOR UPDATE` then `UPDATE`, inside a transaction |
| Conditional decrement on a counter | `UPDATE ... SET value = value - 1 WHERE value > 0`, check affected rows |
| One-per-user bonus | Unique constraint on (user_id, bonus_type) and let the database reject duplicates |
| External non-idempotent call | Idempotency key table plus a transactional write of the result |
| Cross-row consistency | Serializable transaction with explicit retry logic |

## Protect Abuse-friendly Features

Some features are inherently abuse magnets because they dispense value in response to user actions. Referral bonuses, promo codes, signup credits, free trials, email reminders, password reset flows, account recovery paths, and anything that sends messages or makes outbound requests. These need their own controls beyond the authentication controls on the rest of the app.

### Abuse Patterns to Design Against

- **Multi-accounting.** One human creates many accounts to claim one-per-account rewards multiple times. Ask whether your signup flow makes this trivially cheap and consider what signals you have to detect it.
- **Self-referral.** A user refers themselves using a second account. Referral flows should check that referrer and referee are distinguishable humans, not just distinguishable accounts.
- **Coupon stacking.** Multiple promos that were each meant to be used alone get combined to push a price below cost. If your coupon engine allows stacking by default, it's probably a bug.
- **Free trial resets.** A user cancels and re-signs up repeatedly to stay on the free tier forever. Track trial eligibility by something more stable than an email address.
- **Resource exhaustion.** Features that send email, make outbound HTTP calls, trigger webhooks, or run expensive computations on demand are DoS vectors and spam vectors unless rate-limited.
- **Enumeration through behavior.** A password reset endpoint that returns different messages for valid and invalid emails leaks account existence.

### Controls to Apply

- **Per-feature rate limits.** A global rate limit at the edge is not enough. The signup-bonus endpoint, the referral endpoint, the promo-redemption endpoint each need their own limits.
- **Identity signals beyond email.** Device fingerprints, payment-method fingerprints, phone number verification, and KYC verification all carry more signal than email addresses, which are cheap to create in bulk.
- **Audit trails on value-dispensing operations.** Every issued credit, applied promo, or granted bonus should be logged with the triggering user, target user, IP, and timestamp. When abuse is suspected, the log is how you untangle it.
- **Maximums at every layer.** A per-action cap (e.g., one bonus per account) plus a per-account cap (e.g., total lifetime promo value) plus a per-source cap (e.g., per payment method or per device) gives defense in depth.
- **Asymmetric consequences.** Actions that give value should be harder than actions that don't. Making someone wait 30 seconds, or complete a CAPTCHA, to claim a reward is fine. The legitimate user clicks once and moves on; the automated abuser suffers a per-request cost.

## Threat Model from the Business Process

Most threat modeling is done from a technical angle: data flow diagrams, trust boundaries, STRIDE categories. That's useful, but it misses the bugs where the code is technically correct and the process is the problem. Business logic threat modeling asks different questions.

### Questions to Ask Early

- What does a legitimate user do in this feature, step by step?
- What does the system do at each step, and what assumption is it making about the user's intent?
- Which of those assumptions would benefit the user if they were false? (That's where the bugs live.)
- Can the user do things out of order? Skip a step? Repeat a step?
- Can two users act on the same object at the same time?
- Can one user act from two directions at once (e.g., two tabs, two devices)?
- What does this feature produce that has value? (Credits, access, trust, messages, outbound requests.)
- If an adversary tried to exploit this feature for gain, how would they go about it?
- What invariant must always hold (e.g., "a coupon can only be used once", "an account balance can never be negative")? What enforces it, and is that enforcement atomic?

### The "Dishonest User" Exercise

Sit with the feature specification and imagine a user whose only goal is to extract maximum value while staying within the letter of the system's rules. What would they do? What combination of legitimate actions would produce an illegitimate outcome? This is different from thinking about a technical attacker. The dishonest user isn't sending malicious payloads. They're using the app exactly as designed, just in an order or volume the designer didn't anticipate.

### Write Down the Invariants

For any feature that handles value, ownership, or state, write down the invariants in plain English:

- A user cannot approve their own request.
- A coupon code is valid for one redemption per user, and never more than N total.
- A transfer cannot complete if it would leave the source account below zero.
- A workflow reaches the "approved" state only after both reviewer A and reviewer B have approved.

Then for each invariant, identify exactly what code enforces it. If the answer is "the UI" or "the user won't try that", the invariant isn't actually enforced.

## Authorization at the Business-logic Layer

Technical authorization (is this user authenticated, do they have this role) is necessary but not sufficient. Many business logic bugs are authorization bugs in disguise: the user has the general permission to use a feature, but the specific action they're taking violates a rule the system didn't think to check.

### Contextual Authorization

Check not just "can this user do X" but "can this user do X on this object, in this state, right now".

Examples:

- A manager can approve expense reports, but not their own.
- A reviewer can approve a pull request, but not if they authored it.
- A user can cancel an order, but not after it has shipped.
- A user can change their email, but not to an address already in use, and not without verifying the new address.

These checks are part of the business logic, not the authentication layer. They typically require knowledge the auth middleware doesn't have. Keep them close to the operation they guard.

### Avoid "Implicit" Permissions

If two features logically grant the same permission, make sure both are guarded. An internal admin endpoint that's checked carefully is no help if the same operation is reachable through a less-guarded public endpoint.

Map every sensitive operation to every entry point that can trigger it, and verify each entry point enforces the rules. When adding a new entry point (a new API version, an internal tool, a webhook handler), explicitly audit which business rules it needs to apply.

### Reference Related Guidance

For general access control guidance, see the [Access Control Cheat Sheet](Access_Control_Cheat_Sheet.md) and the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md). For the higher-sensitivity case of financial or state-changing transactions, see the [Transaction Authorization Cheat Sheet](Transaction_Authorization_Cheat_Sheet.md).

## Validate Inputs for Business Meaning, Not Just Format

Input validation typically focuses on format: is this a well-formed integer, is this within length limits, does it match a whitelist of characters. That catches injection attacks but not business logic abuse. The input can be perfectly formatted and still semantically invalid.

### Validate Ranges

A quantity can be a positive integer and still be wrong. A discount can be numeric and still absurd. Validate against the meaningful range for the business:

- Quantity must be at least 1 and no more than the stock available.
- Date must be in the future, not more than a year out, not on a blocked day.
- Amount must be positive, not more than the account allows, not above a regulatory limit.
- Text length must match what the downstream system can accept, which may be shorter than a generic limit.

### Validate Combinations

Fields that are individually valid can be collectively invalid. A booking for a valid room with a valid check-in date and a valid check-out date might still be invalid if the check-out precedes the check-in. A transfer between two valid accounts might still be invalid if the accounts belong to different customers and the user lacks permission to act on both.

Write the validation rules that describe legal combinations and enforce them server-side. Unit-test the cases where each individual field is valid but the combination is not.

### Don't Trust Derived or Hidden Fields

Fields that are "not editable in the UI" are fully editable at the HTTP layer. Every field in a request is an input, including the ones in hidden form controls, disabled form controls, fields set by JavaScript, and fields you set in a previous response and expect to receive unchanged. If a field matters, validate it as if it came from an attacker, because it did.

## Observability and Anomaly Detection

Even a well-designed feature will eventually face a creative abuse attempt. Logging and monitoring are what let you notice it and respond.

### What to Log

For any operation that dispenses value, changes permissions, or moves money:

- The authenticated user
- The target resource
- The action taken
- The outcome
- Enough request context to reconstruct what happened (IP, user agent, correlation ID)
- Enough business context to audit (the price computed, the coupon applied, the new state)

These logs should be tamper-evident and separate from general application logs.

### What to Alert On

Rates of the following often precede or accompany abuse:

- Signups from the same IP, device fingerprint, or payment instrument
- Repeated failed password-reset requests from the same source
- Unusually high rates of promo redemptions, referral completions, or credit issuances
- Bursts of requests to a single endpoint from a single user
- Workflows that complete in substantially less time than a human would need

You don't need sophisticated machine learning for this. Simple thresholds on per-user, per-IP, and per-device rates catch most automated abuse.

### Close the Loop

When monitoring surfaces a potential abuse, two things should happen: the specific incident gets investigated and resolved, and the control that should have prevented it gets added or tightened. A detection that doesn't lead to a prevention is a detection you'll be making again next month.

## Testing Business Logic

Automated tests are how business rules stay enforced as the code evolves. Focus test effort on the rules, not the happy path.

### Test the Rules, Not the Implementation

For each invariant you identified during threat modeling, write a test that would fail if the invariant were violated. A test that says "a user cannot approve their own request" should attempt exactly that and assert the request is rejected. These tests document the rules as much as they verify them.

### Test Concurrency

If two requests can race, write a test that races them. Most test frameworks have ways to fire concurrent requests and assert the end state is consistent (e.g., balance is never negative, coupon is redeemed exactly once, bonus is granted exactly once across all winners).

### Test Ordering

For multi-step workflows, test attempts to skip, repeat, and reorder steps. The expected outcome for each is a rejection, not progress.

### Test with an Adversarial Mindset

Unit tests written by the developer who wrote the feature tend to cover cases the developer was already thinking about. A useful complement is adversarial testing: take the feature specification and write tests for the ways a motivated user would try to misuse it. Often the bug reproduces on the first attempt, because the feature wasn't designed with that misuse in mind.

## Common Examples of Business Logic Flaws

Concrete examples help developers recognize the pattern in their own code. The list below is not exhaustive.

### Price and Quantity

- Negative quantity in a cart to get a refund against another item's cost.
- Client-supplied price that the server trusts.
- Zero-price items that are actually valuable because a "free" flag was intended for a different product.
- Currency switching mid-transaction where the amount is kept but the currency changes (e.g., from USD to a much weaker unit).
- Coupon codes applied multiple times, or applied to products they were not meant for.

### Workflow

- Skipping identity verification by calling the post-verification endpoint directly.
- Advancing a job application, approval, or KYC workflow past a stage that was supposed to be gated on a reviewer.
- Triggering "checkout complete" without having actually paid.
- Claiming a reward for a task that was never completed.

### Concurrency

- Withdrawing the same balance from two concurrent sessions.
- Redeeming a single-use voucher from two parallel requests.
- Transferring the same item to two recipients at once.
- Concurrently updating a counter so that one update is lost.

### Authorization-in-disguise

- Approving your own request because the "not the author" check was forgotten.
- Canceling an order after it was supposed to be locked in.
- Modifying a shared resource because the "only the owner can modify" rule was never enforced on a specific endpoint.

### Value-dispensing Abuse

- Claiming a signup bonus multiple times by re-signing up.
- Earning referral rewards by referring yourself.
- Stacking promos that were meant to be mutually exclusive.
- Abusing "refer a friend" mechanics to send spam that looks like it comes from your platform.

## Summary Checklist

Before shipping any feature that handles money, permissions, or state, walkthrough this list:

- Are all security-relevant values (prices, permissions, identity, ownership) derived server-side, not accepted from the client?
- Is every multi-step workflow represented as an explicit state machine in server-side storage, with each transition validated?
- Is every check-then-act operation atomic (transaction, row lock, or conditional update)?
- Do external non-idempotent calls accept an idempotency key?
- Does every value-dispensing feature have a per-action cap, a per-account cap, and a rate limit?
- Are all invariants written down and tested?
- Is every entry point for a sensitive operation subject to the same business rules?
- Does logging capture enough context to reconstruct abuse after the fact, and do alerts fire on anomalous rates?
- Have you considered the dishonest-user perspective, not just the attacker-with-exploit perspective?

## References

- [OWASP Web Security Testing Guide - Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [OWASP Authorization Cheat Sheet](Authorization_Cheat_Sheet.md)
- [OWASP Access Control Cheat Sheet](Access_Control_Cheat_Sheet.md)
- [OWASP Transaction Authorization Cheat Sheet](Transaction_Authorization_Cheat_Sheet.md)
- [OWASP Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md)
- [OWASP Abuse Case Cheat Sheet](Abuse_Case_Cheat_Sheet.md)
