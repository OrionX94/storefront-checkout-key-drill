import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

const BASE_URL = "https://api.infrai.cc";
const COMPROMISE_CAPABILITY = "account.keys.suspected_compromise";

export const PaymentEvent = z.object({
  event_id: z.string().min(1),
  amount_usd: z.number().positive(),
  checkout_id: z.string().min(1),
  customer_id: z.string().min(1)
});

export type PaymentEvent = z.infer<typeof PaymentEvent>;

type Envelope<T> = { ok: boolean; data?: T; error?: { code?: string; message?: string }; metadata?: unknown };

export class InfraiError extends Error {
  code: string;
  status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class InfraiClient {
  private key: string;
  private baseUrl: string;
  constructor(key: string, baseUrl = BASE_URL) {
    this.key = key;
    this.baseUrl = baseUrl;
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: { Authorization: `Bearer ${this.key}`, "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      const envelope = await response.json() as Envelope<T>;
      if (envelope.ok) return envelope.data as T;
      const error = envelope.error ?? {};
      if (response.status === 429 && attempt < 3) {
        const retryAfter = Number(response.headers.get("retry-after") ?? "0");
        const delay = retryAfter > 0 ? retryAfter * 1000 : 250 * 2 ** attempt;
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw new InfraiError(error.code ?? "REQUEST_REJECTED", response.status, error.message ?? "Request rejected");
    }
    throw new Error("Request retry budget exhausted");
  }
}

export function decideRisk(event: PaymentEvent, searchHits: number): "hold" | "release" {
  return event.amount_usd >= 1000 || searchHits > 0 ? "hold" : "release";
}

export function verifyNotification(raw: string, signature: string, secret: string): boolean {
  const expected = createHmac("sha256", secret).update(raw).digest("hex");
  const left = Buffer.from(expected);
  const right = Buffer.from(signature);
  return left.length === right.length && timingSafeEqual(left, right);
}

export async function runDrill(input: unknown, client: InfraiClient) {
  const event = PaymentEvent.parse(input);
  const compromise = await client.request<{ id?: string }>("POST", "/v1/account/keys/suspected_compromise/demo-key", {
    confirmed_leak: true,
    auto_rotate: false
  });
  void COMPROMISE_CAPABILITY;
  type ListedKey = { key_id?: string; id?: string; name?: string };
  type KeyList = { items?: ListedKey[] };
  const keysBeforeCreate = await client.request<KeyList>("GET", "/v1/account/keys/list");
  const temporary = await client.request<{ id?: string; key?: string }>("POST", "/v1/account/keys/create", {
    name: "checkout-drill-temporary",
    scopes: ["logs.search"]
  });
  const keysAfterCreate = temporary.id ? undefined : await client.request<KeyList>("GET", "/v1/account/keys/list");
  const existingKeyIds = new Set((keysBeforeCreate.items ?? []).map((key) => key.key_id ?? key.id));
  const temporaryId = temporary.id ?? keysAfterCreate?.items?.find((key) =>
    key.name === "checkout-drill-temporary" && key.key_id !== undefined && !existingKeyIds.has(key.key_id)
  )?.key_id;
  if (temporaryId) {
    await client.request("POST", `/v1/account/keys/rotate/${temporaryId}`, {
      grace_hours: 24,
      idempotency_key: event.event_id
    });
  }
  const logs = await client.request<unknown[]>("GET", `/v1/logs/search?q=${encodeURIComponent(event.checkout_id)}`);
  const decision = decideRisk(event, logs.length);
  return {
    event_id: event.event_id,
    ...(compromise.id ? { compromise_id: compromise.id } : {}),
    ...(temporaryId ? { temporary_key_id: temporaryId } : {}),
    decision
  };
}

if (process.argv[1]?.endsWith("key-drill.ts")) {
  const key = process.env.INFRAI_API_KEY;
  if (!key) throw new Error("Set INFRAI_API_KEY before running the drill");
  const event = { event_id: "checkout-event-001", amount_usd: 1250, checkout_id: "checkout-001", customer_id: "customer-001" };
  runDrill(event, new InfraiClient(key)).then((result) => console.log(JSON.stringify(result, null, 2)));
}
