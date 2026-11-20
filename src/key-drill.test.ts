import test from "node:test";
import assert from "node:assert/strict";
import { decideRisk, PaymentEvent, verifyNotification } from "./key-drill.ts";
import { createHmac } from "node:crypto";

test("a checkout with a blast-radius hit is held for review", () => {
  const event = PaymentEvent.parse({ event_id: "evt-1", amount_usd: 42, checkout_id: "co-1", customer_id: "cus-1" });
  assert.equal(decideRisk(event, 2), "hold");
  assert.equal(decideRisk(event, 0), "release");
});

test("notification signatures are checked before the audit record is trusted", () => {
  const raw = JSON.stringify({ event_id: "evt-1", status: "held" });
  const signature = createHmac("sha256", "checkout-secret").update(raw).digest("hex");
  assert.equal(verifyNotification(raw, signature, "checkout-secret"), true);
  const alteredLastCharacter = signature.at(-1) === "0" ? "1" : "0";
  assert.equal(verifyNotification(raw, signature.slice(0, -1) + alteredLastCharacter, "checkout-secret"), false);
});
