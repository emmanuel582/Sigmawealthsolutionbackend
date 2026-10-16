# SigmawealthSolution Backend

Next.js frontend: https://sigmawealthsolution.com
Express API: https://sigmawealthsolutionbackend.onrender.com
Payment provider: Bachs. All payment operations share one Supabase ledger on the Express API.

## Deployment

1. Apply supabase/bachs.sql, then supabase/financial-permissions.sql to the existing Supabase project in SQL Editor. For a new project, apply supabase/schema.sql first. Historical transactions are preserved. The permissions migration is required to prevent browser users from changing financial records.
2. Set BACHS_API_KEY, BACHS_WEBHOOK_SECRET, BACHS_CRON_SECRET, NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on Render. Secret keys are server-only.
3. Set FRONTEND_URL=https://sigmawealthsolution.com and PUBLIC_API_URL=https://sigmawealthsolutionbackend.onrender.com on Render.
4. Set SIGMA_API_URL=https://sigmawealthsolutionbackend.onrender.com and the existing NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY on the frontend host.
5. Deploy this backend repository and the Sigmawealthsolution frontend repository together, backend first. Each repository has its own commit.
6. In the matching Bachs environment, register this webhook:

| Setting | Value |
| --- | --- |
| Endpoint | https://sigmawealthsolutionbackend.onrender.com/api/bachs/webhook |
| Event source | all (platform payments and connected investor accounts) |
| Events | checkout.completed, collection.succeeded, collection.failed, payment_method.saved, payout.paid, payout.failed |
| Success return | https://sigmawealthsolution.com/dashboard?bachs_return=1 |
| Cancel return | https://sigmawealthsolution.com/dashboard?bachs_cancel=1 |

Save this endpoint's signing secret as BACHS_WEBHOOK_SECRET. Sandbox and live API keys use separate Bachs environments. Sandbox-first testing is required before real money movement.

## Checkout and auto-debits

Funding accepts exactly NGN 64,000, 98,550, 135,000, 540,000, or 2,160,000. First-time monthly enrollment charges the selected plan amount; later debits use that same plan. Already-funded investors can enroll a card without a second deposit. Old monthly amounts require selecting a current plan before charging resumes. Financial tables are written only through authenticated server routes. Apply the complete migration, including its privilege restrictions. Cards from former providers must be enrolled again with Bachs. Use a separate Supabase project for sandbox testing.

Server records bind each request to its authenticated owner, amount, currency and reference. Provider verification checks settlement. Transactional SQL credits each provider payment once, even when the customer return and webhook arrive concurrently. Never credit a browser return alone or treat a charge's 201 response as paid.

## Investor payouts

Activate Bachs Connect on the platform account and complete the account's requirements. Each investor uses a recipient account with active transfers and payouts capabilities and an approved default NGN bank destination. This implementation preserves NGN amounts and uses Nigerian bank accounts; it does not guess currency conversion rates for returns.

The runner persists one in-app reminder per customer/date on the day before an approved monthly debit, then processes due debits and payouts. The runner reserves each investment/week/date once, quotes the fee, funds the recipient including that fee, and submits the bank payout. Pending payouts stay pending. Only confirmed completion advances the investor's next payout week. Interrupted or uncertain writes must be reconciled by their durable reference; a new cron run cannot resend the same payout.

Enable Automatic in the admin Payouts tab after onboarding is ready. The approved hourly workflow is disabled by default. After Bachs accepts this business and Connect setup is complete, set BACHS_BUSINESS_APPROVED=1 and BACHS_AUTOMATION_ENABLED=1 on Render, set the matching BACHS_CRON_SECRET and SIGMA_API_URL as repository Actions secrets, and set the repository variable BACHS_AUTOMATION_ENABLED=true. Both the runner and API check activation before sending money. Run payouts now uses an authenticated admin session. Existing 5% first-investment referral rewards are paid on Sunday with the same verified payout flow.

Company settlement is separate. Administrators can use GET /api/bachs/settlement-schedule and POST /api/bachs/settlement-schedule with a JSON body such as:

```json
{"interval":"daily","hourUtc":9,"minimumAmount":"5000.00"}
```

The provider schedule uses an approved default company destination and eligible settled customer collections. Transfer-funded investor balances require the investor payout runner. Retain the working balance needed for investor obligations.

## Verification

```bash
npm run check:bachs
npm test
npm run typecheck
npm run build
```

The readiness check is read-only. Tests use isolated local PostgreSQL and mock provider responses; they do not send live charges or payouts. Live acceptance needs Bachs business approval, account and destination verification, available funds, deployment, and end-to-end sandbox testing. Bachs lists investment funds and high-yield programs as prohibited; obtain its explicit acceptance for this investment use case.

The explicit `npm run test:live-bachs` command creates five unpaid checkout sessions using the configured key, retrieves their actual NGN amounts, and checks deployed configuration and admin-route authentication. It never completes payment or creates a bank payout. Results go to reports/bachs-live-test.json. A live key alone does not prove charge delivery, webhook settlement, saved-card debits, or bank payouts.

Dependency installation builds the API to dist/sigma-api.js and Render runs Node directly, so both existing npm-ci services and the supplied Render blueprint have the artifact, including when development dependencies are omitted. Approved administrators must have a confirmed Supabase email, an admin user_roles row, and the same email in admin_allowlist. The public admin registration form cannot grant that role.

Official references: [Checkout](https://docs.bachs.io/guides/checkout/checkout-sessions), [saved-card charges](https://docs.bachs.io/guides/payments/charge-a-saved-card), [webhooks](https://docs.bachs.io/guides/webhooks/overview), [payouts](https://docs.bachs.io/guides/payouts/payout-using-api), [automatic settlement](https://docs.bachs.io/guides/payouts/payout-schedules), [business policy](https://docs.bachs.io/for-you/supported-businesses).

## Local development

```bash
npm install
npm run dev
```

API: http://127.0.0.1:4000. Frontend is in the separate Sigmawealthsolution repository.


## Financial hardening and operational checks

Checkout initiation requires a per-attempt idempotencyKey (16–100 alphanumeric, underscore or hyphen characters). The frontend persists this across retries and refreshes. The backend binds it to the authenticated account and selected plan. Lost provider responses retain the request for reconciliation; never discard a pending attempt and charge again blindly.

Payment and payout calculations use integer minor units and PostgreSQL NUMERIC. Admin contact edits accept only name/phone; account deletion is disabled to preserve financial records. Webhooks have their own rate budget, and provider-read lag returns a retryable response. API JSON bodies are limited to 256 KiB; large images must be compressed before submission. Upstream error bodies and malformed JSON are not copied into logs.

Run npm test for adversarial payment/security tests and npm run test:load for the loopback-only production build burst test. The load test disables external credentials and checks 600 public config/health requests; it does not estimate production checkout capacity. CI runs both.

Run npm run reconcile:bachs -- /absolute/path/to/ignored/.env for a read-only report of the latest 50 checkouts, involved accounts' contribution ledger totals and unfinished payout claims. Exit code 2 means an operator must investigate discrepancies. No charge, transfer, payout or balance mutation is performed by this command. Reconciliation is not scheduled automatically.

The dated reports/security-audit.json records evidence and limits. Production still needs always-on hosting, platform WAF/shared rate limiting, verified Supabase Auth abuse controls, durable log retention, alerting, and backup/restore verification. Instance limits are in memory and are not a distributed limit. Financial tests use PGlite with mocked provider calls; stage real multi-connection PostgreSQL and provider acceptance tests before scaling. Never stress-test the live customer service or enable money movement for a load test.
