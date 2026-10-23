# Simulator payment API

All payment endpoints require `Authorization: Bearer <operator-api-key>`. The key
must belong to an active operator and must not be revoked. Each operator can
access only its own payments. Requests for another operator's payment return the
same 404 as a nonexistent payment.

## Lifecycle

```text
                     succeeded (terminal)
                    /
creation -> pending
                    \
                     failed (terminal)
```

| Method and path                      | Request                                                  | Result                                                    |
| ------------------------------------ | -------------------------------------------------------- | --------------------------------------------------------- |
| `POST /payments`                     | `Idempotency-Key` header and JSON amount/currency        | 201 for a new pending payment; 200 for an identical retry |
| `GET /payments/:paymentId`           | Payment UUID                                             | 200 with the persisted payment                            |
| `POST /payments/:paymentId/simulate` | JSON `{"outcome":"succeeded"}` or `{"outcome":"failed"}` | 200 with the persisted terminal payment                   |

Payment responses contain `id`, `amountMinor`, `currency`, `status`, `provider`,
`createdAt`, and `updatedAt`. Dates use UTC ISO 8601 strings. The provider is always
`simulator`. Creation preserves the existing positive-integer limit of
100,000,000 minor units and three-uppercase-letter currency format. Unknown JSON
fields are rejected. Payment IDs must be UUIDs.

The creation idempotency key must be 8–128 ASCII letters, digits, underscores, or
hyphens. Keys are scoped to the authenticated operator. A retry with a changed
amount or currency returns 409 `idempotency_conflict`; an identical retry returns
the original payment's **current state**, including a completed state, without
resetting it. A new key creates a separate payment.

Simulation is naturally idempotent by payment ID and outcome and does not require
an idempotency header. Repeating the same terminal outcome returns the same
payment without changing `updatedAt`. Attempting to reverse a terminal outcome
returns 409 `invalid_payment_transition`. Existing cancelled records also cannot
be completed through this API. There is no cancellation endpoint in this release.

PostgreSQL row locks serialize competing simulations. Concurrent requests for the
same outcome both return 200; conflicting outcomes produce one 200 and one 409.
Status and `updated_at` change in a single transaction, and failures roll back.
Amount, currency, ownership, and creation idempotency keys are never changed by
simulation. Retrieval reads PostgreSQL rather than process memory.

Other errors use the existing structured format, including a request ID:

- 400: invalid amount, currency shape, UUID, idempotency key, JSON, or simulation body.
- 401: missing/invalid/revoked key or suspended operator.
- 404: payment nonexistent or owned by a different operator.
- 409: idempotency collision or conflicting terminal outcome.
- 500: unexpected persistence failure; internal details are not returned.

## Staging and safety

Normal simulator processing works with `NODE_ENV=production`,
`LIVE_MODE_ENABLED=false`, `ALLOWED_PROVIDERS=simulator`, and
`SIMULATOR_CONTROLS_ENABLED=false`. The simulation endpoint is the simulated
provider's normal operation, not a privileged debug override. An authenticated
operator intentionally chooses the outcome of its own simulated payment.

Existing startup safety checks and the simulator-only database constraint remain
in force. This implementation makes no provider/network calls, accepts no real
provider credentials, and does not transfer funds or update balances.

Existing operator/API-key provisioning is still through the internal
`createOperatorWithApiKey` helper. This change does not add a public administrative
endpoint or seed an operator into staging. Protect the returned raw key and never
log it. No Render configuration or deployed database was changed by this work.

## Database compatibility and verification

**No new migration is needed.** Existing migrations `001_initial_schema.sql` and
`002_operator_api_keys.sql` already provide payment states, timestamps,
operator ownership, API keys, and the unique creation-idempotency constraint.
The existing server applies pending migrations before listening; a previously
migrated staging database requires no schema alteration for this feature.

Run all checks against disposable PostgreSQL 17:

```sh
npm ci
npm run test:isolated -- --check
```

See [testing.md](testing.md) for the isolated database safeguards. Never run the
integration suite against the Render staging database. Tests cover success,
failure, persistence, retries, concurrent duplicates/conflicts, tenant isolation,
invalid input, revoked/suspended credentials, and production-mode simulator safety.
