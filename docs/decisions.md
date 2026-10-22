# Decision log

Short records of important decisions, so anyone can see what was chosen and why.

| #   | Date       | Decision                                                                                | Why                                                               |
| --- | ---------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 1   | 2026-10-22 | Modular monolith: one Express app, one PostgreSQL database, clearly separated modules   | Simplest to build, test and debug; modules can be split out later |
| 2   | 2026-10-22 | TypeScript (strict mode)                                                                | Catches money and data-shape bugs before the code runs            |
| 3   | 2026-10-22 | Knex for queries and migrations (from Step 2)                                           | Beginner-friendly, well documented                                |
| 4   | 2026-10-22 | Vitest + Supertest for tests                                                            | Fast, TypeScript-friendly, tests the HTTP API directly            |
| 5   | 2026-10-22 | npm as package manager                                                                  | Comes with Node.js                                                |
| 6   | 2026-10-22 | EUR only initially; €1 to €10,000 per test payment                                      | Keeps Version 1 small                                             |
| 7   | 2026-10-22 | IDs are random with readable prefixes (`op_`, `pay_`, `key_`)                           | Easy to recognise in logs and support requests                    |
| 8   | 2026-10-22 | Zod validates all configuration; the app refuses to start if anything is unsafe         | Mistakes are caught at start-up, not during a payment             |
| 9   | 2026-10-22 | Real payments are locked off in five independent ways (see Version 1 spec)              | No single mistake can enable real money movement                  |
| 10  | 2026-10-22 | Pino structured logs with redaction; request headers and query strings are never logged | Secrets must never reach log files                                |
| 11  | 2026-10-22 | gitleaks secret scanning locally (pre-commit) and in CI; GitHub push protection         | A leaked secret in Git history cannot be fully undone             |
| 12  | 2026-10-22 | Local Postgres in Docker, bound to 127.0.0.1 only                                       | Not reachable from other devices on your network                  |
| 13  | 2026-10-22 | No real money until the double-entry ledger exists (Version 2)                          | Money movements must be fully auditable                           |
