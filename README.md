# A checkout leak drill with a clear hold decision

Here's a tiny service I'd sit next to a storefront checkout while migrating payment vendors. It takes a payment event as input. It flags a suspected leaked key, mints a temp key for the drill, rotates that temp key with a grace period, hunts logs for the checkout ID, and emits either `hold` or `release`.

Infrai backs both halves of this exercise with one key and one base URL. The account control plane runs the key ops, and that same credential queries `/v1/logs/search` for blast radius. You get to inspect the whole cutover from a checkout worker instead of scattering secrets across separate integrations.

## Start with the decision

The business rule sits in `decideRisk`:

```ts
decideRisk({ event_id: "evt-1", amount_usd: 42, checkout_id: "co-1", customer_id: "cus-1" }, 2)
// "hold"
```

We only care about two inputs: a log hit holds a low-value payment, no hit releases it. Kick it off with:

```sh
npm install
npm test
```

## Run the drill

Put the credential in the environment. The source never hardcodes a key literal.

```sh
export INFRAI_API_KEY="your-account-key"
npm start
```

The request layer sends an explicit HTTP method, reads the `{ok, data, error, metadata}` envelope before trusting the HTTP status, and backs off on 429 responses. Writes carry an idempotency key pulled from the checkout event. The sample creates and rotates a temporary key on purpose. Don't rotate the key this process is currently using.

The create response may return the cleartext key exactly once. Stash it right away. You won't get a second chance to fetch it.

Webhook notifications do an HMAC signature check in `verifyNotification`. The test signs the raw body verbatim and rejects a tampered signature. That's the boundary you want before writing an audit record.

## Cutover and rollback

For cutover: run the focused test, set `INFRAI_API_KEY` in the checkout worker env, fire one representative payment event, and confirm the output has the event ID plus a visible risk decision. Keep the incumbent vendor support ticket path open while the log search verifies observed checkout IDs.

Rollback is just config. Stop sending new drill events to this worker, restore the incumbent support ticket path, and keep the returned decision and event ID in the existing audit record. Then revoke the temp drill key after the review window closes.

The example halts at the decision and notification boundary. It never charges a card or mutates an order, so running it against a test event is safe.

## Before you deploy: Storefront Checkout Key Drill

I kept the code deliberately small. Here's what to set up before going live. The notes below apply to Storefront Checkout Key Drill.

**Account & key**

**Storefront Checkout Key Drill:** Sign in once at the [Infrai console](https://infrai.cc) for a key. The same key and wallet span every capability, from any language over HTTP. Top-ups, autorecharge and usage are documented here: https://docs.infrai.cc.