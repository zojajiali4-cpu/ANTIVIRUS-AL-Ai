import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, createSign, generateKeyPairSync, webcrypto } from "node:crypto";

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto });

const { default: worker } = await import("../src/index.js");
const { readBazaarRefreshToken } = await import("../src/bazaar-oauth.js");
const encoder = new TextEncoder();
const RATE_SALT = "a9".repeat(32);
const PLUS_ENTITLEMENT_HMAC_SECRET = "unit-test-plus-entitlement-secret-32-bytes-min";
const CLIENT_IP = "203.0.113.17";
const KEY_ID = "test-publisher-2026";
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const FEED_PUBLIC_KEY_B64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");

function makeD1({ fail = false } = {}) {
  const counters = new Map();
  const feeds = new Map();
  const statements = [];
  const bazaarVerifications = new Map();
  const oauthStates = new Map();
  let oauthTokenRow = null;
  return {
    statements,
    prepare(sql) {
      if (fail) throw new Error("simulated D1 outage");
      const first = async (params = []) => {
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
        if (sql.startsWith("SELECT subscription_id,expires_at FROM bazaar_subscription_verifications")) {
          return bazaarVerifications.get(params[0]) || null;
        }
        if (sql.startsWith("SELECT iv,ciphertext FROM bazaar_oauth_tokens")) return oauthTokenRow;
        if (sql.startsWith("DELETE FROM bazaar_oauth_states")) {
          const row = oauthStates.get(params[0]);
          if (row && row.expires_at > params[1]) {
            oauthStates.delete(params[0]);
            return { state_hash: params[0] };
          }
          return null;
        }
        return null;
      };
      const run = async (params = []) => {
        if (sql.startsWith("INSERT INTO api_rate_limits")) {
          const key = `${params[0]}:${params[1]}`;
          counters.set(key, (counters.get(key) || 0) + 1);
        } else if (sql.startsWith("INSERT INTO signed_feeds")) {
          feeds.set(params[0], { version: params[0], issued_at: params[1], expires_at: params[2], payload: params[3] });
        } else if (sql.startsWith("INSERT INTO bazaar_subscription_verifications")) {
          bazaarVerifications.set(params[0], {
            purchase_token_sha256: params[0], subscription_id: params[1],
            expires_at: params[2], verified_at: params[3]
          });
        } else if (sql.startsWith("INSERT INTO bazaar_oauth_states")) {
          oauthStates.set(params[0], { state_hash: params[0], expires_at: params[1], created_at: params[2] });
        } else if (sql.startsWith("INSERT INTO bazaar_oauth_tokens")) {
          oauthTokenRow = { iv: params[0], ciphertext: params[1], updated_at: params[2] };
        }
        return { success: true };
      };
      return {
        first: () => first(),
        run: () => run(),
        bind(...params) {
          statements.push({ sql, params });
          return { first: () => first(params), run: () => run(params) };
        }
      };
    }
  };
}

const BAZAAR_MONTHLY = "alai_plus_monthly";
const BAZAAR_ANNUAL = "alai_plus_annual";

function bazaarEnvironment(db = makeD1()) {
  return {
    DB: db, RATE_SALT,
    BAZAAR_CLIENT_ID: "test-client-id",
    BAZAAR_CLIENT_SECRET: "test-client-secret",
    BAZAAR_REFRESH_TOKEN: "test-refresh-token",
    BAZAAR_PACKAGE_NAME: "com.antivirusalai",
    BAZAAR_SUBSCRIPTION_MONTHLY_ID: BAZAAR_MONTHLY,
    BAZAAR_SUBSCRIPTION_ANNUAL_ID: BAZAAR_ANNUAL,
    PLUS_ENTITLEMENT_HMAC_SECRET
  };
}

function signedPlusAccessToken(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    v: 1, aud: "antivirus-al-ai:hash-reputation",
    productId: BAZAAR_MONTHLY, packageName: "com.antivirusalai",
    iat: now, exp: now + 300, subscriptionExpiresAt: now + 3600,
    ...overrides
  };
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = createHmac("sha256", PLUS_ENTITLEMENT_HMAC_SECRET).update(encoded).digest("base64url");
  return encoded + "." + signature;
}
function plusAuthorization(token = signedPlusAccessToken()) {
  return { authorization: "Bearer " + token };
}

async function withBazaarApi(subscription, callback, { tokenStatus = 200, subscriptionStatus = 200 } = {}) {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, method: init.method || "GET", body: init.body });
    if (url === "https://pardakht.cafebazaar.ir/devapi/v2/auth/token/") {
      return new Response(JSON.stringify(
        tokenStatus === 200
          ? { access_token: "test-bazaar-access-token", token_type: "Bearer", expires_in: 3600 }
          : { error: "invalid_client" }
      ), { status: tokenStatus, headers: { "content-type": "application/json" } });
    }
    if (url.includes("/devapi/v2/api/applications/com.antivirusalai/subscriptions/")) {
      return new Response(JSON.stringify(subscription || {}), {
        status: subscriptionStatus, headers: { "content-type": "application/json" }
      });
    }
    throw new Error("Unexpected Cafe Bazaar API URL: " + url);
  };
  try { return await callback(calls); }
  finally { globalThis.fetch = originalFetch; }
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

function signedFeed({ version = 7, issued = Math.floor(Date.now() / 1000) - 60, expires = Math.floor(Date.now() / 1000) + 86_400, keyId = KEY_ID } = {}) {
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

test("Cafe Bazaar OAuth start requires the owner setup key and uses the exact registered redirect URI", async () => {
  const db = makeD1();
  const env = {
    ...bazaarEnvironment(db),
    BAZAAR_OAUTH_REDIRECT_URI: "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback",
    BAZAAR_OAUTH_SETUP_KEY: "owner-setup-key-for-cafe-bazaar-oauth-32",
    BAZAAR_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64url")
  };
  const page = await worker.fetch(new Request(
    "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/start",
    { headers: { "CF-Connecting-IP": CLIENT_IP } }
  ), env);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /type="password"/);

  const denied = await worker.fetch(new Request(
    "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/start",
    { method: "POST", headers: {
      "CF-Connecting-IP": CLIENT_IP, Origin: "https://antivirus-al-ai-api.zojajiali4.workers.dev",
      "content-type": "application/x-www-form-urlencoded"
    }, body: "setup_key=wrong" }
  ), env);
  assert.equal(denied.status, 403);

  const started = await worker.fetch(new Request(
    "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/start",
    { method: "POST", headers: {
      "CF-Connecting-IP": CLIENT_IP, Origin: "https://antivirus-al-ai-api.zojajiali4.workers.dev",
      "content-type": "application/x-www-form-urlencoded"
    }, body: "setup_key=" + encodeURIComponent(env.BAZAAR_OAUTH_SETUP_KEY) }
  ), env);
  assert.equal(started.status, 303);
  const location = new URL(started.headers.get("location"));
  assert.equal(location.origin, "https://pardakht.cafebazaar.ir");
  assert.equal(location.pathname, "/devapi/v2/auth/authorize/");
  assert.equal(location.searchParams.get("response_type"), "code");
  assert.equal(location.searchParams.get("access_type"), "offline");
  assert.equal(location.searchParams.get("redirect_uri"), env.BAZAAR_OAUTH_REDIRECT_URI);
  assert.equal(location.searchParams.get("client_id"), env.BAZAAR_CLIENT_ID);
  assert.equal(location.searchParams.get("state")?.length, 43);
  assert.match(started.headers.get("set-cookie"), /HttpOnly/);
  assert.match(started.headers.get("set-cookie"), /SameSite=Lax/);
});

test("Cafe Bazaar OAuth callback exchanges a one-time code and encrypts the refresh token at rest", async () => {
  const db = makeD1();
  const env = {
    ...bazaarEnvironment(db),
    BAZAAR_OAUTH_REDIRECT_URI: "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback",
    BAZAAR_OAUTH_SETUP_KEY: "owner-setup-key-for-cafe-bazaar-oauth-32",
    BAZAAR_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64url")
  };
  const start = await worker.fetch(new Request(
    "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/start",
    { method: "POST", headers: {
      "CF-Connecting-IP": CLIENT_IP, Origin: "https://antivirus-al-ai-api.zojajiali4.workers.dev",
      "content-type": "application/x-www-form-urlencoded"
    }, body: "setup_key=" + encodeURIComponent(env.BAZAAR_OAUTH_SETUP_KEY) }
  ), env);
  assert.equal(start.status, 303);
  const authUrl = new URL(start.headers.get("location"));
  const state = authUrl.searchParams.get("state");
  const cookie = start.headers.get("set-cookie").split(";")[0];
  const originalFetch = globalThis.fetch;
  let exchangeBody = "";
  globalThis.fetch = async (input, init = {}) => {
    assert.equal(String(input), "https://pardakht.cafebazaar.ir/devapi/v2/auth/token/");
    exchangeBody = String(init.body);
    return new Response(JSON.stringify({
      access_token: "short-lived-access-token",
      refresh_token: "refresh-token-that-must-never-be-returned-to-browser",
      token_type: "Bearer", expires_in: 3600
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const callback = await worker.fetch(new Request(
      "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback?code=one-time-auth-code-123456&state=" + encodeURIComponent(state),
      { headers: { "CF-Connecting-IP": CLIENT_IP, cookie } }
    ), env);
    assert.equal(callback.status, 200);
    const page = await callback.text();
    assert.match(page, /با موفقیت انجام شد/);
    assert.doesNotMatch(page, /refresh-token-that-must-never-be-returned/);
    assert.match(exchangeBody, /grant_type=authorization_code/);
    assert.match(exchangeBody, /redirect_uri=https%3A%2F%2Fantivirus-al-ai-api/);
    const stored = await readBazaarRefreshToken(env);
    assert.equal(stored, "refresh-token-that-must-never-be-returned-to-browser");
    assert.notEqual(db.statements.find(x => x.sql.startsWith("INSERT INTO bazaar_oauth_tokens"))?.params[1], stored);
    const replay = await worker.fetch(new Request(
      "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback?code=one-time-auth-code-123456&state=" + encodeURIComponent(state),
      { headers: { "CF-Connecting-IP": CLIENT_IP, cookie } }
    ), env);
    assert.equal(replay.status, 400);
  } finally { globalThis.fetch = originalFetch; }
});

test("Cafe Bazaar OAuth callback rejects a state mismatch before contacting Bazaar", async () => {
  const env = {
    ...bazaarEnvironment(),
    BAZAAR_OAUTH_REDIRECT_URI: "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback",
    BAZAAR_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 11).toString("base64url")
  };
  const response = await worker.fetch(new Request(
    "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback?code=one-time-auth-code-123456&state=attacker-state-value",
    { headers: { "CF-Connecting-IP": CLIENT_IP, cookie: "__Host-alai-bazaar-oauth=other-state-value" } }
  ), env);
  assert.equal(response.status, 400);
});

test("Cafe Bazaar billing readiness stays closed when server configuration is missing", async () => {
  const env = bazaarEnvironment();
  delete env.BAZAAR_CLIENT_SECRET;
  const response = await worker.fetch(request("/v1/billing/bazaar/status"), env);
  assert.equal(response.status, 200);
  const result = await json(response);
  assert.equal(result.checkoutReady, false);
  assert.equal(result.reason, "NOT_CONFIGURED");
});

test("Cafe Bazaar billing readiness validates credentials and returns configured SKUs", async () => {
  const env = bazaarEnvironment();
  await withBazaarApi(null, async calls => {
    const response = await worker.fetch(request("/v1/billing/bazaar/status"), env);
    assert.equal(response.status, 200);
    const result = await json(response);
    assert.equal(result.checkoutReady, true);
    assert.equal(result.monthlySku, BAZAAR_MONTHLY);
    assert.equal(result.annualSku, BAZAAR_ANNUAL);
    assert.equal(calls[0].method, "POST");
    assert.match(calls[0].body, /grant_type=refresh_token/);
  });
});

test("Cafe Bazaar subscription verification validates with Bazaar and issues a short-lived PLUS token", async () => {
  const db = makeD1(), env = bazaarEnvironment(db);
  const purchaseToken = "bazaar-purchase-token-123456789";
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  await withBazaarApi({
    kind: "androidpublisher#subscriptionPurchase",
    validUntilTimestampMsec: String(expiresAt),
    autoRenewing: true,
    initiationTimestampMsec: String(Date.now() - 1000)
  }, async calls => {
    const response = await worker.fetch(
      request("/v1/billing/bazaar/verify", {
        subscriptionId: BAZAAR_MONTHLY, purchaseToken
      }), env
    );
    assert.equal(response.status, 200);
    const result = await json(response);
    assert.equal(result.ok, true);
    assert.equal(result.entitled, true);
    assert.equal(result.subscriptionId, BAZAAR_MONTHLY);
    assert.equal(result.expiresAtEpochMillis, expiresAt);
    assert.equal(typeof result.cloudAccessToken, "string");
    const lookup = await worker.fetch(
      request("/v1/hash/reputation", { sha256: "f".repeat(64) }, plusAuthorization(result.cloudAccessToken)),
      env
    );
    assert.equal(lookup.status, 200);
    assert.equal((await json(lookup)).classification, "UNKNOWN");
    assert.equal(calls.length, 2);
    assert.ok(calls[0].url.endsWith("/devapi/v2/auth/token/"));
    assert.ok(calls[1].url.includes("/subscriptions/" + BAZAAR_MONTHLY + "/purchases/"));
  });
  const insert = db.statements.find(item => item.sql.startsWith("INSERT INTO bazaar_subscription_verifications"));
  assert.ok(insert);
  assert.notEqual(insert.params[0], purchaseToken);
  assert.equal(insert.params.includes(purchaseToken), false);
  assert.match(insert.params[0], /^[a-f0-9]{64}$/);
});

test("Cafe Bazaar purchase-token validation allows ordinary opaque tokens and rejects whitespace/control characters", async () => {
  const env = bazaarEnvironment();
  await withBazaarApi({
    kind: "androidpublisher#subscriptionPurchase",
    validUntilTimestampMsec: String(Date.now() + 7 * 24 * 60 * 60 * 1000),
    autoRenewing: true
  }, async () => {
    const response = await worker.fetch(request("/v1/billing/bazaar/verify", {
      subscriptionId: BAZAAR_MONTHLY,
      purchaseToken: "opaque-token-containing-s-and-x-123456789"
    }), env);
    assert.equal(response.status, 200);
  });
  const invalidTokens = [
    "opaque-token-with whitespace-123456789",
    "opaque-token-with" + String.fromCharCode(10) + "newline-123456789",
    "opaque-token-with" + String.fromCharCode(1) + "control-123456789"
  ];
  for (const purchaseToken of invalidTokens) {
    const response = await worker.fetch(request("/v1/billing/bazaar/verify", {
      subscriptionId: BAZAAR_MONTHLY, purchaseToken
    }), env);
    assert.equal(response.status, 400);
    assert.equal((await json(response)).error, "PURCHASE_TOKEN_INVALID");
  }
});

test("Cafe Bazaar subscription verification rejects unknown product IDs before network access", async () => {
  const env = bazaarEnvironment();
  const response = await worker.fetch(
    request("/v1/billing/bazaar/verify", {
      subscriptionId: "attacker-product", purchaseToken: "bazaar-purchase-token-123456789"
    }), env
  );
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "SUBSCRIPTION_NOT_ALLOWED");
});

test("Cafe Bazaar subscription verification rejects a response with an unexpected resource kind", async () => {
  const env = bazaarEnvironment();
  await withBazaarApi({
    kind: "unexpected-resource",
    validUntilTimestampMsec: String(Date.now() + 7 * 24 * 60 * 60 * 1000),
    autoRenewing: true
  }, async () => {
    const response = await worker.fetch(
      request("/v1/billing/bazaar/verify", {
        subscriptionId: BAZAAR_MONTHLY,
        purchaseToken: "bazaar-purchase-token-123456789"
      }), env
    );
    assert.equal(response.status, 502);
    assert.equal((await json(response)).error, "BAZAAR_PURCHASE_RESPONSE_INVALID");
  });
});

test("Cafe Bazaar subscription verification rejects expired subscription periods", async () => {
  const env = bazaarEnvironment();
  await withBazaarApi({
    kind: "androidpublisher#subscriptionPurchase",
    validUntilTimestampMsec: String(Date.now() - 1000),
    autoRenewing: false
  }, async () => {
    const response = await worker.fetch(
      request("/v1/billing/bazaar/verify", {
        subscriptionId: BAZAAR_ANNUAL,
        purchaseToken: "bazaar-purchase-token-123456789"
      }), env
    );
    assert.equal(response.status, 403);
    assert.equal((await json(response)).error, "PURCHASE_NOT_ENTITLED");
  });
});

test("Cafe Bazaar subscription verification fails closed when OAuth credentials are rejected", async () => {
  const env = bazaarEnvironment();
  await withBazaarApi(null, async () => {
    const response = await worker.fetch(
      request("/v1/billing/bazaar/verify", {
        subscriptionId: BAZAAR_MONTHLY,
        purchaseToken: "bazaar-purchase-token-123456789"
      }), env
    );
    assert.equal(response.status, 503);
  }, { tokenStatus: 401 });
});

test("hash reputation rejects absent, forged, expired and wrong-product PLUS tokens before DB lookup", async () => {
  const db = makeD1(), env = bazaarEnvironment(db);
  const now = Math.floor(Date.now() / 1000);
  const cases = [
    {},
    plusAuthorization("not-a-token.signature"),
    plusAuthorization(signedPlusAccessToken({ exp: now - 1 })),
    plusAuthorization(signedPlusAccessToken({ subscriptionExpiresAt: now - 1 })),
    plusAuthorization(signedPlusAccessToken({ productId: "other-product" })),
    plusAuthorization(signedPlusAccessToken({ aud: "other-api" }))
  ];
  for (const headers of cases) {
    const response = await worker.fetch(
      request("/v1/hash/reputation", { sha256: "f".repeat(64) }, headers), env
    );
    assert.equal(response.status, 403);
    assert.equal((await json(response)).error, "PLUS_ENTITLEMENT_REQUIRED");
  }
  assert.equal(db.statements.some(item => item.sql.startsWith(
    "SELECT classification,family_id,source,updated_at FROM hash_reputation"
  )), false);
});

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
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "b".repeat(64) }, plusAuthorization()),
    bazaarEnvironment(db)
  );
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
    const env = bazaarEnvironment();
    let lastResponse;
    for (let index = 0; index < 61; index += 1) {
      lastResponse = await worker.fetch(
        request("/v1/hash/reputation", { sha256: "d".repeat(64) }, plusAuthorization()), env
      );
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
  const tampered = payload.replace("TEST.FAMILY", "TEST.FAMILZ");
  const response = await worker.fetch(request("/v1/admin/feed", { payload: tampered }, { authorization: "Bearer test-admin-token" }), feedEnvironment());
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
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "a".repeat(70_000) }, plusAuthorization()),
    bazaarEnvironment()
  );
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "BODY_TOO_LARGE");
});


test("an absent hash reputation record remains UNKNOWN, never clean", async () => {
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "f".repeat(64) }, plusAuthorization()),
    bazaarEnvironment()
  );
  assert.equal(response.status, 200);
  const result = await json(response);
  assert.equal(result.found, false);
  assert.equal(result.classification, "UNKNOWN");
  assert.match(result.disclaimer, /not proof of safety/i);
});

test("URL analysis is structural only and does not fetch the submitted URL", async () => {
  const response = await worker.fetch(request("/v1/url/check", { url: "https://example.com/account" }), { DB: makeD1(), RATE_SALT });
  assert.equal(response.status, 200);
  const result = await json(response);
  assert.equal(result.scope, "STRUCTURAL_ANALYSIS_AND_CURATED_REPUTATION");
  assert.equal(result.assessment.level, "CAUTION");
  assert.ok(result.assessment.signals.includes("SENSITIVE_KEYWORD"));
  assert.match(result.disclaimer, /No URL was opened or fetched/i);
});

test("URL analysis flags literal-IP HTTP URLs as high-risk structure", async () => {
  const response = await worker.fetch(request("/v1/url/check", { url: "http://192.0.2.10/login" }), { DB: makeD1(), RATE_SALT });
  assert.equal(response.status, 200);
  const result = await json(response);
  assert.equal(result.assessment.level, "HIGH_RISK_STRUCTURE");
  assert.ok(result.assessment.signals.includes("IP_LITERAL_HOST"));
  assert.ok(result.assessment.signals.includes("UNENCRYPTED_HTTP"));
});

test("URL analysis rejects unsupported schemes without attempting a fetch", async () => {
  const response = await worker.fetch(request("/v1/url/check", { url: "javascript:alert(1)" }), { DB: makeD1(), RATE_SALT });
  assert.equal(response.status, 400);
  const result = await json(response);
  assert.equal(result.assessment.level, "INVALID");
  assert.ok(result.assessment.signals.includes("UNSUPPORTED_SCHEME"));
});

test("hash reputation rejects malformed digests", async () => {
  const response = await worker.fetch(
    request("/v1/hash/reputation", { sha256: "not-a-hash" }, plusAuthorization()),
    bazaarEnvironment()
  );
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "INVALID_SHA256");
});

test("CORS preflight reflects only an explicitly allowed origin", async () => {
  const allowed = await worker.fetch(new Request("https://api.example.test/v1/hash/reputation", {
    method: "OPTIONS", headers: { Origin: "https://app.example.test" }
  }), { CORS_ALLOWED_ORIGINS: "https://app.example.test" });
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://app.example.test");

  const denied = await worker.fetch(new Request("https://api.example.test/v1/hash/reputation", {
    method: "OPTIONS", headers: { Origin: "https://evil.example" }
  }), { CORS_ALLOWED_ORIGINS: "https://app.example.test" });
  assert.equal(denied.status, 204);
  assert.equal(denied.headers.get("access-control-allow-origin"), null);
});
