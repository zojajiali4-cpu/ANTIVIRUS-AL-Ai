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
  const billingVerifications = new Map();
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
        return null;
      };
      const run = async (params = []) => {
        if (sql.startsWith("INSERT INTO api_rate_limits")) {
          const key = `${params[0]}:${params[1]}`;
          counters.set(key, (counters.get(key) || 0) + 1);
        } else if (sql.startsWith("INSERT INTO signed_feeds")) {
          feeds.set(params[0], { version: params[0], issued_at: params[1], expires_at: params[2], payload: params[3] });
        } else if (sql.startsWith("INSERT INTO play_billing_verifications")) {
          billingVerifications.set(params[0], {
            token_hash: params[0], product_id: params[1], base_plan_id: params[2],
            subscription_state: params[3], expires_at: params[4], is_trial: params[5],
            created_at: params[6], updated_at: params[7]
          });
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
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "a".repeat(70_000) }), { DB: makeD1(), RATE_SALT });
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "BODY_TOO_LARGE");
});


test("an absent hash reputation record remains UNKNOWN, never clean", async () => {
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "f".repeat(64) }), { DB: makeD1(), RATE_SALT });
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
  const response = await worker.fetch(request("/v1/hash/reputation", { sha256: "not-a-hash" }), { DB: makeD1(), RATE_SALT });
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


const { privateKey: playServicePrivateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const playServiceAccount = JSON.stringify({
  type: "service_account",
  client_email: "alai-billing@test-project.iam.gserviceaccount.com",
  private_key_id: "test-key-id",
  private_key: playServicePrivateKey.export({ type: "pkcs8", format: "pem" })
});
function playBillingEnvironment(db = makeD1()) {
  return {
    DB: db, RATE_SALT,
    PLAY_PACKAGE_NAME: "com.antivirusalai",
    PLAY_SUBSCRIPTION_PRODUCT_ID: "alai_plus",
    PLAY_SUBSCRIPTION_BASE_PLANS: "monthly,annual",
    PLAY_SERVICE_ACCOUNT_JSON: playServiceAccount
  };
}
async function withPlayApi(purchase, callback, {
  failAck = false,
  status = 200,
  subscriptionStatus = 200,
  subscriptionConfig = {
    packageName: "com.antivirusalai",
    productId: "alai_plus",
    basePlans: [
      { basePlanId: "monthly", state: "ACTIVE" },
      { basePlanId: "annual", state: "ACTIVE" }
    ]
  }
} = {}) {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, method: init.method || "GET" });
    if (url === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "test-play-access-token", expires_in: 3600 }), {
        status: 200, headers: { "content-type": "application/json" }
      });
    }
    if (url.includes(":acknowledge")) {
      return new Response(failAck ? JSON.stringify({ error: "ack failed" }) : "{}", {
        status: failAck ? 503 : 200, headers: { "content-type": "application/json" }
      });
    }
    if (url.includes("/applications/com.antivirusalai/subscriptions/alai_plus")) {
      return new Response(subscriptionStatus === 200 ? JSON.stringify(subscriptionConfig) : "{}",
        { status: subscriptionStatus, headers: { "content-type": "application/json" } });
    }
    if (url.includes("/purchases/subscriptionsv2/tokens/")) {
      return new Response(status === 200 ? JSON.stringify(purchase || {}) : "{}", {
        status, headers: { "content-type": "application/json" }
      });
    }
    throw new Error("Unexpected test URL");
  };
  try { return await callback(calls); }
  finally { globalThis.fetch = originalFetch; }
}
function subscriptionFixture(overrides = {}) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  return {
    subscriptionState: "SUBSCRIPTION_STATE_ACTIVE",
    acknowledgementState: "ACKNOWLEDGEMENT_STATE_PENDING",
    lineItems: [{
      productId: "alai_plus",
      expiryTime: expiresAt,
      offerDetails: { basePlanId: "monthly", offerId: "trial-7d" },
      offerPhase: { freeTrial: {} }
    }],
    ...overrides
  };
}

test("Play subscription verification fails closed when server credentials are absent", async () => {
  const response = await worker.fetch(
    request("/v1/billing/subscription/verify", {
      productId: "alai_plus", purchaseToken: "play-token-123456789012345"
    }),
    { DB: makeD1(), RATE_SALT }
  );
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "BILLING_NOT_CONFIGURED");
});

test("Play subscription verification rejects product IDs outside the configured product", async () => {
  const response = await worker.fetch(
    request("/v1/billing/subscription/verify", {
      productId: "attacker_product", purchaseToken: "play-token-123456789012345"
    }),
    playBillingEnvironment()
  );
  assert.equal(response.status, 400);
  assert.equal((await json(response)).error, "PRODUCT_NOT_ALLOWED");
});

test("Play subscription verification validates with Google, acknowledges, and stores only a token digest", async () => {
  const db = makeD1(), env = playBillingEnvironment(db);
  const purchaseToken = "play-token-123456789012345";
  await withPlayApi(subscriptionFixture(), async calls => {
    const response = await worker.fetch(
      request("/v1/billing/subscription/verify", { productId: "alai_plus", purchaseToken }),
      env
    );
    assert.equal(response.status, 200);
    const result = await json(response);
    assert.equal(result.ok, true);
    assert.equal(result.entitled, true);
    assert.equal(result.isTrial, true);
    assert.equal(result.basePlanId, "monthly");
    assert.equal(result.acknowledgementState, "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED");
    assert.ok(calls.some(call => call.method === "POST" && call.url.includes(":acknowledge")));
  });
  const insert = db.statements.find(item => item.sql.startsWith("INSERT INTO play_billing_verifications"));
  assert.ok(insert);
  assert.notEqual(insert.params[0], purchaseToken);
  assert.equal(insert.params.includes(purchaseToken), false);
  assert.match(insert.params[0], /^[a-f0-9]{64}$/);
});

test("Play subscription verification refuses unconfigured base plans", async () => {
  const env = playBillingEnvironment();
  env.PLAY_SUBSCRIPTION_BASE_PLANS = "";
  const response = await worker.fetch(
    request("/v1/billing/subscription/verify", {
      productId: "alai_plus", purchaseToken: "play-token-123456789012345"
    }),
    env
  );
  assert.equal(response.status, 503);
  assert.equal((await json(response)).error, "BILLING_NOT_CONFIGURED");
});

test("Play subscription verification never grants access to an expired subscription", async () => {
  const expired = subscriptionFixture({
    acknowledgementState: "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
    lineItems: [{
      productId: "alai_plus",
      expiryTime: new Date(Date.now() - 60_000).toISOString(),
      offerDetails: { basePlanId: "monthly" },
      offerPhase: { freeTrial: {} }
    }]
  });
  await withPlayApi(expired, async () => {
    const response = await worker.fetch(
      request("/v1/billing/subscription/verify", {
        productId: "alai_plus", purchaseToken: "play-token-expired-123456789"
      }),
      playBillingEnvironment()
    );
    assert.equal(response.status, 200);
    assert.equal((await json(response)).entitled, false);
  });
});

test("Play subscription verification accepts canceled subscriptions only until their expiry", async () => {
  const canceled = subscriptionFixture({
    subscriptionState: "SUBSCRIPTION_STATE_CANCELED",
    acknowledgementState: "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"
  });
  await withPlayApi(canceled, async () => {
    const response = await worker.fetch(
      request("/v1/billing/subscription/verify", {
        productId: "alai_plus", purchaseToken: "play-token-canceled-123456789"
      }),
      playBillingEnvironment()
    );
    assert.equal(response.status, 200);
    assert.equal((await json(response)).entitled, true);
  });
});

test("Play subscription verification does not grant access to pending, on-hold, or paused subscriptions", async () => {
  for (const state of ["SUBSCRIPTION_STATE_PENDING", "SUBSCRIPTION_STATE_ON_HOLD", "SUBSCRIPTION_STATE_PAUSED"]) {
    const fixture = subscriptionFixture({ subscriptionState: state });
    await withPlayApi(fixture, async () => {
      const response = await worker.fetch(
        request("/v1/billing/subscription/verify", {
          productId: "alai_plus", purchaseToken: "play-token-" + state.toLowerCase() + "-123456789"
        }),
        playBillingEnvironment()
      );
      assert.equal(response.status, 200);
      assert.equal((await json(response)).entitled, false);
    });
  }
});

test("Play subscription verification rejects a Google purchase for another product", async () => {
  const mismatch = subscriptionFixture({
    lineItems: [{
      productId: "other_product",
      expiryTime: new Date(Date.now() + 60_000).toISOString(),
      offerDetails: { basePlanId: "monthly" }
    }]
  });
  await withPlayApi(mismatch, async () => {
    const response = await worker.fetch(
      request("/v1/billing/subscription/verify", {
        productId: "alai_plus", purchaseToken: "play-token-wrongproduct-123456"
      }),
      playBillingEnvironment()
    );
    assert.equal(response.status, 400);
    assert.equal((await json(response)).error, "PURCHASE_PRODUCT_MISMATCH");
  });
});

test("Play subscription verification fails closed when Google acknowledgement fails", async () => {
  await withPlayApi(subscriptionFixture(), async () => {
    const response = await worker.fetch(
      request("/v1/billing/subscription/verify", {
        productId: "alai_plus", purchaseToken: "play-token-ackfailure-123456789"
      }),
      playBillingEnvironment()
    );
    assert.equal(response.status, 503);
    assert.equal((await json(response)).error, "PURCHASE_ACKNOWLEDGEMENT_PENDING");
  }, { failAck: true });
});

test("Play subscription verification maps unknown Google purchase tokens to an invalid purchase", async () => {
  await withPlayApi({}, async () => {
    const response = await worker.fetch(
      request("/v1/billing/subscription/verify", {
        productId: "alai_plus", purchaseToken: "play-token-notfound-123456789"
      }),
      playBillingEnvironment()
    );
    assert.equal(response.status, 400);
    assert.equal((await json(response)).error, "INVALID_PURCHASE_TOKEN");
  }, { status: 404 });
});


test("billing readiness stays closed until the Google Play product and active base plans are verified", async () => {
  await withPlayApi(null, async calls => {
    const response = await worker.fetch(request("/v1/billing/status"), playBillingEnvironment());
    assert.equal(response.status, 200);
    const result = await json(response);
    assert.equal(result.ok, true);
    assert.equal(result.checkoutReady, true);
    assert.deepEqual(result.activeBasePlans, ["annual", "monthly"]);
    assert.ok(calls.some(call => call.url.endsWith("/applications/com.antivirusalai/subscriptions/alai_plus")));
  });
});

test("billing readiness exposes only configured base plans that Google marks ACTIVE", async () => {
  await withPlayApi(null, async () => {
    const response = await worker.fetch(request("/v1/billing/status"), playBillingEnvironment());
    assert.equal(response.status, 200);
    const result = await json(response);
    assert.equal(result.checkoutReady, true);
    assert.deepEqual(result.activeBasePlans, ["monthly"]);
  }, {
    subscriptionConfig: {
      packageName: "com.antivirusalai",
      productId: "alai_plus",
      basePlans: [
        { basePlanId: "monthly", state: "ACTIVE" },
        { basePlanId: "annual", state: "INACTIVE" },
        { basePlanId: "legacy", state: "ACTIVE" }
      ]
    }
  });
});

test("billing readiness stays closed when Google Play has no active supported base plan", async () => {
  await withPlayApi(null, async () => {
    const response = await worker.fetch(request("/v1/billing/status"), playBillingEnvironment());
    assert.equal(response.status, 200);
    const result = await json(response);
    assert.equal(result.checkoutReady, false);
    assert.deepEqual(result.activeBasePlans, []);
  }, {
    subscriptionConfig: {
      packageName: "com.antivirusalai",
      productId: "alai_plus",
      basePlans: [
        { basePlanId: "monthly", state: "INACTIVE" },
        { basePlanId: "annual", state: "INACTIVE" }
      ]
    }
  });
});

test("billing readiness fails closed when Google Play Publisher API is unavailable", async () => {
  await withPlayApi(null, async () => {
    const response = await worker.fetch(request("/v1/billing/status"), playBillingEnvironment());
    assert.equal(response.status, 503);
    assert.equal((await json(response)).checkoutReady, false);
  }, { subscriptionStatus: 403 });
});

test("billing readiness never reports configured when the service account is missing", async () => {
  const env = playBillingEnvironment();
  delete env.PLAY_SERVICE_ACCOUNT_JSON;
  const response = await worker.fetch(request("/v1/billing/status"), env);
  assert.equal(response.status, 200);
  const result = await json(response);
  assert.equal(result.checkoutReady, false);
  assert.deepEqual(result.activeBasePlans, []);
});
