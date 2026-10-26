# VaultX Pay · Phase 2 synthetic PSP preview

**Every account, permission, terminal, payment, report and action is simulated.** This standalone demonstration never imports or starts the gateway, reads environment credentials, accesses PostgreSQL, sends email, contacts a provider, or enables a feature gate. All state exists only in memory. Closing the window or choosing Reset discards changes.

## Windows: open the preview

1. Install **Node.js 24 LTS** from <https://nodejs.org/> if it is not already installed. Do not change security policy or run as administrator.
2. Extract the whole ZIP to a normal folder on your computer.
3. Double-click **Preview-Dashboard.cmd**. Keep its window open.
4. Open **http://127.0.0.1:4175/** in your browser.
5. To stop, click the command window and press **Ctrl+C**.

No npm install, source build, Git command, PowerShell script, database, real account or password is required. If port 4175 is occupied, the preview stops; close the other preview yourself rather than exposing it elsewhere. Never enter real credentials. The launcher deliberately requires Node 24 and binds only to 127.0.0.1.

## Demonstrate all three levels

1. Choose **Open demo owner**. Create `Aurora Retail · Demo` in the Merchant directory. You can suspend a merchant and permanently withdraw its payment-read entitlement in this disposable runtime. Withdrawal invalidates its sessions and removes the permission from its users; reactivation does not restore it.
2. Choose **Switch demo account**, select your new merchant and **Open demo merchant**.
3. In **Team & permissions**, create an invitation for `Taylor · Demo`. This is a local invitation record only; no email is sent.
4. Switch demo account and choose **Activate Taylor · Demo**. The synthetic account initially has no permissions or terminals.
5. Open the same merchant again. In Team & permissions, select `payments.read`, `payments.simulate`, `finance.read`, `audit.read` and a terminal for Taylor. Save assignments.
6. Switch demo account, select Taylor and **Open demo submerchant**. A new merchant has no fabricated transactions. Use the prepopulated Northstar merchant and create a user there to explore realistic existing synthetic transactions, or choose prepopulated Alex.
7. Open **Transactions**, filter/search, paginate and investigate a pending payment. A user with both payment read and simulate permissions can simulate success or failure exactly once. Attempts, local webhook visibility and an audit event update. No HTTP webhook or payment is sent.
8. Switch to the merchant and remove the user's permissions or disable the account. Prior sessions are invalidated. Reopen the submerchant: data/action access is denied. Cross-terminal and cross-merchant rows are never returned.
9. Open **Audit activity** with an authorized role. Owner sees all synthetic events; merchant users see only their merchant's events.

To demonstrate the entire transaction workflow in one merchant, create the invitation in **Northstar Commerce · Demo**, which contains the transaction fixtures. New merchant accounts intentionally start with no transactions.

## Screens and honest limits

Owner overview / Merchant directory / Client accounts / Security policies / Audit; Merchant overview / Team & permissions / Terminal access / Transactions / Account settings; Submerchant PSP overview / Transactions / Finance & settlement / Audit.

This is a functional interaction prototype, **not production authentication or production authorization implementation**. The role picker intentionally provides synthetic access with no password. Real MFA/enrollment, email invitation delivery, credential resets/recovery, production ledger and durable audits are not represented. Withdrawal/refund/cascading/settlement data is not invented: unavailable functionality is explicitly labeled. Financial totals group currencies separately. Local webhook status is only an in-memory demonstration, never real delivery. There is no network provider, create-payment API, refund, withdrawal, balance mutation or real account provisioning.

All account sessions and policy changes are local demo-only. Setting production environment variables has no effect on this package. It does not replace independent review or tests of the gateway's actual security model.

Optional: close the running preview and double-click **Test-Preview.cmd** for built-in credential-free HTTP/security smoke tests. Browser tests run in CI using externally installed Playwright; no browser automation dependency is needed to open the preview.
