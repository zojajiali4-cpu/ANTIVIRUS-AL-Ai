import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync, webcrypto } from "node:crypto";

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto });

const { default: worker } = await import("../src/index.js");
const encoder = new TextEncoder();
const RATE_SALT = "a9".repeat(32);
const CLIENT_IP = "203.0.113.17";
const KEY_ID = "test-publisher-2026";
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const FEED_PUBLIC_KEY_B64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");

function makeD1({ fail = false } = {}) {
  const counters = new Map();
  const feeds = new Map();
  const statements = [];
  return {
    statements,
    prepare(sql) {
      if (fail) throw new Error("simulated D1 outage");
      return {
        bind(...params) {
          statements.push({ sql, params });
          return {
            async run() {
              if (sql.startsWith("INSERT INTO api_rate_limits")) {
                const key = `${params[0]}:${params[1]}`;
                counters.set(key, (counters.get(key) || 0) + 1);
              } else if (sql.startsWith("INSERT INTO signed_feeds")) {
                feeds.set(params[0], { version: params[0], issued_at: params[1], expires_at: params[2], payload: params[3] });
              }
              return { success: true };
            },
            async first() {
              if (sql.startsWith("SELECT hits FROM api_rate_limits")) {
                const key = `${params[0]}:${params[1]}`;
                return { hits: counters.get(key) || 0 };
              }
              if (sql.startsWith("SELECT MAX(version) AS v FROM signed_feeds")) {
                return { v: feeds.size ? Math.max(...feeds.keys()) : null };
              }
              if (sql.startsWith("SELECT version,expires_at,payload FROM signed_feeds")) {
                return [...feeds.values()].sort((a,b)=>b.version-a.version)[0] || null;
              }
              return null;
            }
          };
        }
      };
    }
  };
}

function request(path, body = undefined, headers = {}) {
  return new Request(`https://api.example.test${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      "CF-Connecting-IP": CLIENT_IP,
      ...headers
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function json(response) { return response.json(); }

async function expectedHmac(ip, secret) {
  const key = await webcrypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await webcrypto.subtle.sign("HMAC", key, encoder.encode(ip));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function signedFeed({ version = 7, issued = 1_800_000_000, expires = 1_800_604_800, keyId = KEY_ID } = {}) {
  const payload = [
    "ALAI-THREAT-FEED/1",
    `key_id=${keyId}`,
    `version=${version}`,
    `issued_at=${issued}`,
    `expires_at=${expires}`,
    `entry=${"a".repeat(64)}|TEST.FAMILY|MALWARE`
  ].join("\n") + "\n";
  const signer = createSign("SHA256");
  signer.update(payload);
  signer.end();
  const signature = signer.sign(privateKey).toString("base64");
  return payload + `signature=${signature}\n`;
}

function feedEnvironment(db = makeD1()) {
  return { DB: db, RATE_SALT, ADMIN_API_KEY: "test-admin-token", FEED_KEY_ID: KEY_ID, FEED_PUBLIC_KEY_B64 };
}

test("health remains available without D1 or a rate-limit key", async () => {
  const response = await worker.fetch(new Request("https://api.example.test/v1/health"), {});
  assert.equal(response.status, 200);
  assert.equal((await json(response)).ok, true);
});

test("protected API fails closed when D1 is unavailable", async () => {
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "a".repeat(64) }), { RATE_SALT });
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "DATABASE_UNAVAILABLE");
});

test("protected API fails closed when RATE_SALT is missing or too short", async () => {
  for (const salt of [undefined, "short-secret"]) {
    const response = await worker.fetch(request("/v1/url/check", { url: "https://example.com" }), { DB: makeD1(), RATE_SALT: salt });
    assert.equal(response.status, 503);
    assert.equal((await json(response)).error, "RATE_LIMIT_KEY_NOT_CONFIGURED");
  }
});

test("rate-limit identifier is HMAC-SHA256, not an unkeyed IP digest", async () => {
  const db = makeD1();
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "b".repeat(64) }), { DB: db, RATE_SALT });
  assert.equal(response.status, 200);
  const insert = db.statements.find(item => item.sql.startsWith("INSERT INTO api_rate_limits"));
  assert.ok(insert);
  const storedIdentifier = insert.params[0];
  assert.equal(storedIdentifier, await expectedHmac(CLIENT_IP, RATE_SALT));
  assert.notEqual(storedIdentifier, createHash("sha256").update(CLIENT_IP).digest("hex"));
});

test("rate-limit storage failure refuses the protected request", async () => {
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "c".repeat(64) }), { DB: makeD1({ fail: true }), RATE_SALT });
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
      lastResponse = await worker.fetch(request("/v1/hash/reputation", { sha256: "d".repeat(64) }), env);
    }
    assert.equal(lastResponse.status, 429);
    assert.equal((await json(lastResponse)).error, "RATE_LIMITED");
  } finally { Date.now = originalNow; }
});

test("missing client IP fails closed", async () => {
  const response = await worker.fetch(new Request("https://api.example.test/v1/hash/reputation", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sha256: "e".repeat(64) })
  }), { DB: makeD1(), RATE_SALT });
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "CLIENT_ADDRESS_UNAVAILABLE");
});

test("admin feed publishing rejects missing authentication", async () => {
  const response = await worker.fetch(request("/v1/admin/feed", { payload: signedFeed() }), feedEnvironment());
  assert.equal(response.status, 401);
  assert.equal((await json(response)).error, "UNAUTHORIZED");
});

test("admin feed publishing requires a configured verification key", async () => {
  const env = feedEnvironment();
  delete env.FEED_PUBLIC_KEY_B64;
  const response = await worker.fetch(request("/v1/admin/feed", { payload: signedFeed() }, { authorization: "Bearer test-admin-token" }), env);
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "FEED_VERIFICATION_NOT_CONFIGURED");
});

test("admin feed publishing accepts a valid ECDSA P-256 signature and serves the feed", async () => {
  const db = makeD1(), env = feedEnvironment(db), payload = signedFeed();
  const response = await worker.fetch(request("/v1/admin/feed", { payload }, { authorization: "Bearer test-admin-token" }), env);
  assert.equal(response.status, 200);
  assert.deepEqual(await json(response), { ok: true, version: 7, signatureVerified: true });

  const latest = await worker.fetch(request("/v1/threat-feed/latest"), env);
  assert.equal(latest.status, 200);
  assert.equal(await latest.text(), payload);
});

test("admin feed publishing rejects a tampered signature", async () => {
  const payload = signedFeed();
  const lines = payload.trimEnd().split("\n");
  const signature = lines.at(-1).slice("signature=".length);
  lines[lines.length - 1] = `signature=${(signature[0] === "A" ? "B" : "A") + signature.slice(1)}`;
  const response = await worker.fetch(request("/v1/admin/feed", { payload: lines.join("\n") + "\n" }, { authorization: "Bearer test-admin-token" }), feedEnvironment());
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "INVALID_FEED_SIGNATURE");
});

test("admin feed publishing rejects an unpinned key identifier", async () => {
  const response = await worker.fetch(request("/v1/admin/feed", { payload: signedFeed({ keyId: "attacker-key" }) }, { authorization: "Bearer test-admin-token" }), feedEnvironment());
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "UNTRUSTED_FEED_KEY");
});

test("admin feed publishing rejects expired or excessive-lifetime feeds", async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const payload of [
    signedFeed({ issued: now - 7200, expires: now - 1 }),
    signedFeed({ issued: now - 1, expires: now + 31 * 24 * 60 * 60 })
  ]) {
    const response = await worker.fetch(request("/v1/admin/feed", { payload }, { authorization: "Bearer test-admin-token" }), feedEnvironment());
    assert.equal(response.status, 400);
    assert.equal((await json(response)).error, "INVALID_FEED_DATES");
  }
});

test("admin feed publishing prevents version rollback", async () => {
  const env = feedEnvironment();
  const first = await worker.fetch(request("/v1/admin/feed", { payload: signedFeed({ version: 9 }) }, { authorization: "Bearer test-admin-token" }), env);
  assert.equal(first.status, 200);
  const rollback = await worker.fetch(request("/v1/admin/feed", { payload: signedFeed({ version: 9 }) }, { authorization: "Bearer test-admin-token" }), env);
  assert.equal(rollback.status, 409);
  assert.equal((await json(rollback)).error, "VERSION_ROLLBACK");
});

test("request bodies are bounded before JSON parsing", async () => {
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "a".repeat(70_000) }), { DB: makeD1(), RATE_SALT });
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "BODY_TOO_LARGE");
});
