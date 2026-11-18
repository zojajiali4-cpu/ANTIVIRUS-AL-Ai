import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const { default: worker } = await import("../src/index.js");
const encoder = new TextEncoder();
const RATE_SALT = "d3".repeat(32);
const CLIENT_IP = "198.51.100.23";
const ORDER_ID = "123e4567-e89b-42d3-a456-426614174000";

function makeD1({ planExists = true } = {}) {
  const counters = new Map();
  const statements = [];
  return {
    statements,
    prepare(sql) {
      return {
        bind(...params) {
          statements.push({ sql, params });
          return {
            async run() {
              if (sql.startsWith("INSERT INTO billing_rate_limits")) {
                const key = `${params[0]}:${params[1]}:${params[2]}`;
                counters.set(key, (counters.get(key) || 0) + 1);
              }
              return { success: true };
            },
            async first() {
              if (sql.startsWith("SELECT hits FROM billing_rate_limits")) {
                const key = `${params[0]}:${params[1]}:${params[2]}`;
                return { hits: counters.get(key) || 0 };
              }
              if (sql.startsWith("SELECT code,name,interval FROM plans")) {
                return planExists
                  ? { code: params[0], name: "PLUS Monthly", interval: "month" }
                  : null;
              }
              if (sql.startsWith("SELECT id FROM customers")) return { id: "customer-test" };
              return null;
            }
          };
        }
      };
    }
  };
}

function apiRequest(path, method = "GET", body = undefined, headers = {}) {
  return new Request(`https://billing.example.test${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      "CF-Connecting-IP": CLIENT_IP,
      ...headers
    },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body)
  });
}

async function json(response) {
  return response.json();
}

async function hmacHex(value, secret) {
  const key = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await webcrypto.subtle.sign("HMAC", key, encoder.encode(value));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

test("health endpoint remains available without payment infrastructure", async () => {
  const response = await worker.fetch(apiRequest("/api/health"), {});
  assert.equal(response.status, 200);
  assert.equal((await json(response)).status, "ok");
});

test("checkout fails closed when the billing rate-limit secret is missing", async () => {
  const response = await worker.fetch(
    apiRequest("/api/checkout", "POST", {
      email: "buyer@example.com",
      plan: "PLUS_MONTHLY",
      provider: "zarinpal",
      locale: "en"
    }),
    { DB: makeD1(), PRICE_PLUS_MONTHLY_IRR: "250000" }
  );
  assert.equal(response.status, 503);
  assert.match((await json(response)).error, /unavailable/i);
});

test("valid plan reaches the payment configuration gate (regression for plan lookup argument order)", async () => {
  const response = await worker.fetch(
    apiRequest("/api/checkout", "POST", {
      email: "buyer@example.com",
      plan: "PLUS_MONTHLY",
      provider: "zarinpal",
      locale: "en"
    }),
    {
      DB: makeD1(),
      RATE_SALT,
      PRICE_PLUS_MONTHLY_IRR: "250000"
      // No ZARINPAL_MERCHANT_ID: payment is intentionally disabled in tests.
    }
  );
  assert.equal(response.status, 503);
  assert.match((await json(response)).error, /domestic payments are not configured/i);
});

test("unknown plan is rejected before any payment provider call", async () => {
  const response = await worker.fetch(
    apiRequest("/api/checkout", "POST", {
      email: "buyer@example.com",
      plan: "UNSUPPORTED_PLAN",
      provider: "zarinpal",
      locale: "en"
    }),
    {
      DB: makeD1({ planExists: false }),
      RATE_SALT,
      PRICE_PLUS_MONTHLY_IRR: "250000"
    }
  );
  assert.equal(response.status, 409);
});

test("order status uses POST body rather than exposing customer email in query string", async () => {
  const env = { DB: makeD1(), RATE_SALT };
  const getResponse = await worker.fetch(
    apiRequest(`/api/order-status?order=${ORDER_ID}&email=buyer%40example.com`),
    env
  );
  assert.equal(getResponse.status, 404);

  const postResponse = await worker.fetch(
    apiRequest("/api/order-status", "POST", {
      order: ORDER_ID,
      email: "buyer@example.com"
    }),
    env
  );
  assert.equal(postResponse.status, 404);
  assert.equal((await json(postResponse)).error, "Order not found.");
});

test("checkout rejects oversized and malformed JSON bodies", async () => {
  const env = { DB: makeD1(), RATE_SALT, PRICE_PLUS_MONTHLY_IRR: "250000" };
  const tooLarge = await worker.fetch(
    apiRequest("/api/checkout", "POST", "x".repeat(12_100)),
    env
  );
  assert.equal(tooLarge.status, 400);

  const malformed = await worker.fetch(
    apiRequest("/api/checkout", "POST", "{invalid-json"),
    env
  );
  assert.equal(malformed.status, 400);
});

test("billing rate-limit identifier is a keyed HMAC of the client IP", async () => {
  const db = makeD1();
  const response = await worker.fetch(
    apiRequest("/api/checkout", "POST", {
      email: "buyer@example.com",
      plan: "PLUS_MONTHLY",
      provider: "zarinpal",
      locale: "en"
    }),
    { DB: db, RATE_SALT, PRICE_PLUS_MONTHLY_IRR: "250000" }
  );
  assert.equal(response.status, 503);
  const insert = db.statements.find(statement => statement.sql.startsWith("INSERT INTO billing_rate_limits"));
  assert.ok(insert);
  assert.equal(insert.params[0], await hmacHex(CLIENT_IP, RATE_SALT));
  assert.equal(insert.params[2], "checkout");
});

test("checkout rate limit rejects the eleventh request in one minute", async () => {
  const originalNow = Date.now;
  Date.now = () => 1_800_000_000_000;
  try {
    const env = { DB: makeD1(), RATE_SALT, PRICE_PLUS_MONTHLY_IRR: "250000" };
    let response;
    for (let index = 0; index < 11; index += 1) {
      response = await worker.fetch(
        apiRequest("/api/checkout", "POST", {
          email: "buyer@example.com",
          plan: "PLUS_MONTHLY",
          provider: "zarinpal",
          locale: "en"
        }),
        env
      );
    }
    assert.equal(response.status, 429);
  } finally {
    Date.now = originalNow;
  }
});

test("Stripe webhook accepts any valid v1 signature in the header", async () => {
  const originalNow = Date.now;
  Date.now = () => 1_800_000_000_000;
  try {
    const secret = "stripe-webhook-test-secret";
    const timestamp = String(Math.floor(Date.now() / 1000));
    const raw = JSON.stringify({ type: "ignored.test.event" });
    const expected = await hmacHex(`${timestamp}.${raw}`, secret);
    const response = await worker.fetch(
      apiRequest(
        "/api/webhooks/stripe",
        "POST",
        raw,
        { "Stripe-Signature": `t=${timestamp},v1=${"0".repeat(64)},v1=${expected}` }
      ),
      { STRIPE_WEBHOOK_SECRET: secret }
    );
    assert.equal(response.status, 200);
    assert.equal((await json(response)).received, true);
  } finally {
    Date.now = originalNow;
  }
});

test("Stripe webhook rejects an invalid signature", async () => {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const response = await worker.fetch(
    apiRequest(
      "/api/webhooks/stripe",
      "POST",
      JSON.stringify({ type: "ignored.test.event" }),
      { "Stripe-Signature": `t=${timestamp},v1=${"0".repeat(64)}` }
    ),
    { STRIPE_WEBHOOK_SECRET: "stripe-webhook-test-secret" }
  );
  assert.equal(response.status, 400);
});
