import test from "node:test";
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const { default: worker } = await import("../src/index.js");
const encoder = new TextEncoder();
const RATE_SALT = "a9".repeat(32);
const CLIENT_IP = "203.0.113.17";

function makeD1({ fail = false } = {}) {
  const counters = new Map();
  const statements = [];
  return {
    statements,
    async prepare(sql) {
      if (fail) throw new Error("simulated D1 outage");
      return {
        bind(...params) {
          statements.push({ sql, params });
          return {
            async run() {
              if (sql.startsWith("INSERT INTO api_rate_limits")) {
                const key = `${params[0]}:${params[1]}`;
                counters.set(key, (counters.get(key) || 0) + 1);
              }
              return { success: true };
            },
            async first() {
              if (sql.startsWith("SELECT hits FROM api_rate_limits")) {
                const key = `${params[0]}:${params[1]}`;
                return { hits: counters.get(key) || 0 };
              }
              return null;
            }
          };
        }
      };
    }
  };
}

function request(path, body = undefined) {
  return new Request(`https://api.example.test${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      "CF-Connecting-IP": CLIENT_IP
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function json(response) {
  return response.json();
}

async function expectedHmac(ip, secret) {
  const key = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await webcrypto.subtle.sign("HMAC", key, encoder.encode(ip));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

test("health remains available without D1 or a rate-limit key", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/v1/health"),
    {}
  );
  assert.equal(response.status, 200);
  assert.equal((await json(response)).ok, true);
});

test("protected API fails closed when D1 is unavailable", async () => {
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "a".repeat(64) }),
    { RATE_SALT }
  );
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "DATABASE_UNAVAILABLE");
});

test("protected API fails closed when RATE_SALT is missing or too short", async () => {
  for (const salt of [undefined, "short-secret"]) {
    const response = await worker.fetch(
      request("/v1/url/check", { url: "https://example.com" }),
      { DB: makeD1(), RATE_SALT: salt }
    );
    assert.equal(response.status, 503);
    assert.equal((await json(response)).error, "RATE_LIMIT_KEY_NOT_CONFIGURED");
  }
});

test("rate-limit identifier is HMAC-SHA256, not an unkeyed IP digest", async () => {
  const db = makeD1();
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "b".repeat(64) }),
    { DB: db, RATE_SALT }
  );

  assert.equal(response.status, 200);
  const insert = db.statements.find(item => item.sql.startsWith("INSERT INTO api_rate_limits"));
  assert.ok(insert, "the rate-limit insert should be executed");
  const storedIdentifier = insert.params[0];
  assert.equal(storedIdentifier, await expectedHmac(CLIENT_IP, RATE_SALT));
  assert.notEqual(
    storedIdentifier,
    createHash("sha256").update(CLIENT_IP).digest("hex"),
    "the stored identifier must not be a plain SHA-256 hash of the IP"
  );
});

test("rate-limit storage failure refuses the protected request", async () => {
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "c".repeat(64) }),
    { DB: makeD1({ fail: true }), RATE_SALT }
  );
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "RATE_LIMIT_STORAGE_UNAVAILABLE");
});

test("the 61st request in a minute is rate limited", async () => {
  const originalNow = Date.now;
  Date.now = () => 1_800_000_000_000;
  try {
    const env = { DB: makeD1(), RATE_SALT };
    let lastResponse;
    for (let index = 0; index < 61; index += 1) {
      lastResponse = await worker.fetch(
        request("/v1/hash/reputation", { sha256: "d".repeat(64) }),
        env
      );
    }
    assert.equal(lastResponse.status, 429);
    assert.equal((await json(lastResponse)).error, "RATE_LIMITED");
  } finally {
    Date.now = originalNow;
  }
});

test("missing client IP fails closed", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/v1/hash/reputation", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sha256: "e".repeat(64) })
    }),
    { DB: makeD1(), RATE_SALT }
  );
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "CLIENT_ADDRESS_UNAVAILABLE");
});
