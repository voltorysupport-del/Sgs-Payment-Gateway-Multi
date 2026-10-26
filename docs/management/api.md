# Owner management HTTP boundary

Depends on the management domain foundation. `OWNER_ENABLED` defaults to false. Enabling it requires exact HTTPS `OWNER_ORIGIN`, an explicit client `DASHBOARD_PUBLIC_ORIGIN` on a different hostname, and development/test mode. Configuration and router both refuse production enablement. Existing `DASHBOARD_TRUSTED_PROXIES` remains an explicit IP/CIDR allowlist used by the shared Express ingress; do not trust arbitrary hops or forwarded hosts. No existing dashboard gate is enabled by this code.

Requests require TLS (directly or through an explicitly trusted proxy), the exact raw configured owner Host, allowed Origin/Fetch-Metadata and a separate `__Host-vaultx_owner_session` cookie. Client cookies and Bearer keys never confer owner authority. All writes additionally require exact owner Origin, current owner CSRF token and JSON. Bodies are bounded to 4 KB with compressed input disabled. Unknown fields, malformed IDs, query arrays and unsupported methods including HEAD/OPTIONS fail closed. Responses are sanitized JSON with `Cache-Control: no-store`; no generic proxy exists.

| Route                                                      | Methods | Authority/behavior                                                                                                 |
| ---------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------ |
| `/owner-api/auth/me`                                       | GET     | Current owner subject and exact platform permissions; not a login                                                  |
| `/owner-api/auth/csrf`                                     | GET     | Rotate CSRF verifier for an already authenticated owner                                                            |
| `/owner-api/auth/logout`                                   | POST    | Current CSRF; invalidate session and clear host-only Secure/HttpOnly/SameSite=Strict cookie                        |
| `/owner-api/clients`                                       | GET     | `platform.clients.read`; bounded directory                                                                         |
| `/owner-api/clients/:id`                                   | GET     | `platform.clients.read`; operator metadata                                                                         |
| `/owner-api/clients/:id`                                   | PATCH   | `platform.clients.manage`, fresh MFA, CSRF, expectedVersion; strict optional name/status                           |
| `/owner-api/clients/:id/members`                           | GET     | `platform.clients.read`; target-scoped retained memberships and grant metadata                                     |
| `/owner-api/clients/:id/members/:membershipId`             | GET     | Same authority and exact tenant/member relationship                                                                |
| `/owner-api/clients/:id/entitlements/:permission/withdraw` | POST    | `platform.clients.manage`, fresh MFA, CSRF, expectedVersion; permanently withdraw payment-read/status-read ceiling |
| `/owner-api/audit`                                         | GET     | `platform.audit.read`; bounded minimized successful-operation history                                              |

Authentication and permission checks repeat inside the operation's database transaction, not only in HTTP middleware. Lists default to 20, have API maximum 50 and offset maximum 10,000. The owner UI uses fixed pages of 20. Unsupported account creation, login/enrollment/recovery, administrator promotion/delegation/regrant, machine credentials and payments have no endpoints. There is no operator-ID authority accepted from client sessions: an owner target selector is validated only after independent platform authority.

On an uncertain write response, do not automatically retry. Revalidate the owner identity and retrieve the current resource version/audit before a new explicit decision. A stale expectedVersion prevents replay of committed writes. Error messages and logs omit request bodies and underlying database details. See the domain document for expiry, lock protocol, audit limits and deferred production prerequisites.
