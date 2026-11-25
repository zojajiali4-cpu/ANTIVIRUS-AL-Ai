const AUTHORIZE_URL = "https://pardakht.cafebazaar.ir/devapi/v2/auth/authorize/";
const TOKEN_URL = "https://pardakht.cafebazaar.ir/devapi/v2/auth/token/";
const COOKIE = "__Host-alai-bazaar-oauth";
const DEFAULT_REDIRECT_URI = "https://antivirus-al-ai-api.zojajiali4.workers.dev/v1/billing/bazaar/oauth/callback";
const MAX_FORM_BYTES = 4096;
const MAX_TOKEN_RESPONSE_BYTES = 16384;
const encoder = new TextEncoder();

function response(body, status = 200, headers = {}) {
  return new Response(body, { status, headers: {
    "cache-control": "no-store, max-age=0",
    "content-security-policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    ...headers
  }});
}

function html(message, status = 200) {
  const safe = String(message).replace(/[&<>"]/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"
  })[c]);
  return response("<!doctype html><html lang=\"fa\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ANTIVIRUS AL AI</title><body><main><h1>ANTIVIRUS AL AI</h1><p>" + safe + "</p></main></body></html>", status, {
    "content-type": "text/html; charset=utf-8"
  });
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value, expectedBytes = null) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error("OAUTH_ENCRYPTION_KEY_INVALID");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  let binary;
  try { binary = atob(base64); } catch { throw Error("OAUTH_ENCRYPTION_KEY_INVALID"); }
  if (expectedBytes !== null && binary.length !== expectedBytes) throw Error("OAUTH_ENCRYPTION_KEY_INVALID");
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function encryptionKey(env) {
  const raw = decodeBase64Url(env.BAZAAR_TOKEN_ENCRYPTION_KEY, 32);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function storeBazaarRefreshToken(env, refreshToken) {
  if (!env.DB || typeof refreshToken !== "string" || !refreshToken.length || refreshToken.length > 8192) {
    throw Error("BAZAAR_TOKEN_STORAGE_UNAVAILABLE");
  }
  const key = await encryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(refreshToken));
  await env.DB.prepare(
    "INSERT INTO bazaar_oauth_tokens(id,iv,ciphertext,updated_at) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET iv=excluded.iv,ciphertext=excluded.ciphertext,updated_at=excluded.updated_at"
  ).bind(base64Url(iv), base64Url(new Uint8Array(ciphertext)), Math.floor(Date.now() / 1000)).run();
}

export async function readBazaarRefreshToken(env) {
  if (env.DB) {
    const row = await env.DB.prepare("SELECT iv,ciphertext FROM bazaar_oauth_tokens WHERE id=1").first();
    if (row?.iv && row?.ciphertext) {
      const key = await encryptionKey(env);
      const iv = decodeBase64Url(row.iv, 12);
      if (row.ciphertext.length > 12000) throw Error("BAZAAR_TOKEN_STORAGE_INVALID");
      const encrypted = decodeBase64Url(row.ciphertext);
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
      const token = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      if (!token || token.length > 8192) throw Error("BAZAAR_TOKEN_STORAGE_INVALID");
      return token;
    }
  }
  if (typeof env.BAZAAR_REFRESH_TOKEN === "string" && env.BAZAAR_REFRESH_TOKEN.trim()) {
    return env.BAZAAR_REFRESH_TOKEN.trim();
  }
  throw Error("BAZAAR_REFRESH_TOKEN_NOT_CONFIGURED");
}

function equalSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = encoder.encode(a), right = encoder.encode(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) diff |= (left[i] || 0) ^ (right[i] || 0);
  return diff === 0;
}

function cookieValue(header, name) {
  for (const part of (header || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return "";
}

async function readSmallForm(req) {
  const length = req.headers.get("content-length");
  if (length && Number(length) > MAX_FORM_BYTES) throw Error("FORM_TOO_LARGE");
  const reader = req.body?.getReader();
  if (!reader) return new URLSearchParams();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_FORM_BYTES) {
        await reader.cancel();
        throw Error("FORM_TOO_LARGE");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new URLSearchParams(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function redirectLocation(clientId, redirectUri, state) {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("state", state);
  return url.toString();
}

async function start(req, env) {
  if (req.method === "GET") {
    return response(
      "<!doctype html><html lang=\"fa\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>اتصال امن کافه‌بازار</title><body><main><h1>اتصال امن کافه‌بازار</h1><p>برای شروع مجوزدهی، کلید راه‌اندازی اختصاصی را وارد کنید. این کلید فقط با درخواست HTTPS به سرور ارسال می‌شود.</p><form method=\"post\" action=\"/v1/billing/bazaar/oauth/start\"><label>کلید راه‌اندازی <input type=\"password\" name=\"setup_key\" autocomplete=\"current-password\" required minlength=\"32\"></label><button type=\"submit\">ادامه و ورود به کافه‌بازار</button></form></main></body></html>",
      200, { "content-type": "text/html; charset=utf-8" }
    );
  }
  if (req.method !== "POST") return html("درخواست پشتیبانی نمی‌شود.", 405);
  const redirectUri = env.BAZAAR_OAUTH_REDIRECT_URI || DEFAULT_REDIRECT_URI;
  let parsed;
  try { parsed = new URL(redirectUri); } catch { return html("تنظیم مسیر بازگشت معتبر نیست.", 503); }
  if (parsed.protocol !== "https:" || parsed.pathname !== "/v1/billing/bazaar/oauth/callback" ||
      req.headers.get("Origin") !== parsed.origin) return html("درخواست مبدأ نامعتبر است.", 403);
  if (!env.DB || !env.BAZAAR_CLIENT_ID || !env.BAZAAR_CLIENT_SECRET ||
      typeof env.BAZAAR_OAUTH_SETUP_KEY !== "string" || env.BAZAAR_OAUTH_SETUP_KEY.length < 32 ||
      !env.BAZAAR_TOKEN_ENCRYPTION_KEY) {
    return html("تنظیمات اتصال سرور کامل نیست.", 503);
  }
  try { await encryptionKey(env); } catch { return html("کلید رمزنگاری سرور معتبر نیست.", 503); }
  const form = await readSmallForm(req);
  if (!equalSecret(form.get("setup_key"), env.BAZAAR_OAUTH_SETUP_KEY)) {
    return html("کلید راه‌اندازی نادرست است.", 403);
  }
  const state = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const stateHash = await sha256Hex(state);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM bazaar_oauth_states WHERE expires_at<=?").bind(now).run();
  await env.DB.prepare(
    "INSERT INTO bazaar_oauth_states(state_hash,expires_at,created_at) VALUES(?,?,?)"
  ).bind(stateHash, now + 600, now).run();
  return response(null, 303, {
    "location": redirectLocation(env.BAZAAR_CLIENT_ID, redirectUri, state),
    "set-cookie": COOKIE + "=" + state + "; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax"
  });
}

async function callback(req, env) {
  if (req.method !== "GET") return html("درخواست پشتیبانی نمی‌شود.", 405);
  const url = new URL(req.url);
  const state = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  const cookie = cookieValue(req.headers.get("cookie"), COOKIE);
  const clearCookie = COOKIE + "=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax";
  if (!state || state.length > 128 || !equalSecret(state, cookie) ||
      !/^[\x21-\x7E]{8,4096}$/.test(code)) {
    return html("پاسخ مجوزدهی معتبر نیست؛ فرایند را دوباره آغاز کنید.", 400);
  }
  if (!env.DB || !env.BAZAAR_CLIENT_ID || !env.BAZAAR_CLIENT_SECRET ||
      !(env.BAZAAR_OAUTH_REDIRECT_URI || DEFAULT_REDIRECT_URI) || !env.BAZAAR_TOKEN_ENCRYPTION_KEY) {
    return html("تنظیمات اتصال سرور کامل نیست.", 503, { "set-cookie": clearCookie });
  }
  const stateHash = await sha256Hex(state);
  const consumed = await env.DB.prepare(
    "DELETE FROM bazaar_oauth_states WHERE state_hash=? AND expires_at>? RETURNING state_hash"
  ).bind(stateHash, Math.floor(Date.now() / 1000)).first();
  if (!consumed) return html("این درخواست منقضی شده یا قبلاً استفاده شده است.", 400, { "set-cookie": clearCookie });

  const providerError = url.searchParams.get("error");
  if (providerError) return html("مجوز کافه‌بازار تأیید نشد. در صورت نیاز دوباره تلاش کنید.", 400, { "set-cookie": clearCookie });

  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: env.BAZAAR_CLIENT_ID,
    client_secret: env.BAZAAR_CLIENT_SECRET,
    redirect_uri: redirectUri
  });
  let tokenResponse;
  try {
    const upstream = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "accept": "application/json" },
      body: form.toString(),
      redirect: "manual"
    });
    const raw = await upstream.text();
    if (encoder.encode(raw).byteLength > MAX_TOKEN_RESPONSE_BYTES || !upstream.ok) {
      return html("کافه‌بازار مجوز را نپذیرفت. تنظیمات کلاینت را بررسی کنید.", 502, { "set-cookie": clearCookie });
    }
    tokenResponse = JSON.parse(raw);
  } catch {
    return html("ارتباط امن با کافه‌بازار برقرار نشد. بعداً دوباره تلاش کنید.", 502, { "set-cookie": clearCookie });
  }
  if (!tokenResponse || typeof tokenResponse.refresh_token !== "string" ||
      !tokenResponse.refresh_token.length || tokenResponse.refresh_token.length > 8192 ||
      typeof tokenResponse.access_token !== "string" || !tokenResponse.access_token.length) {
    return html("پاسخ توکن کافه‌بازار معتبر نبود.", 502, { "set-cookie": clearCookie });
  }
  try {
    await storeBazaarRefreshToken(env, tokenResponse.refresh_token);
  } catch {
    return html("ذخیره امن مجوز انجام نشد؛ تنظیمات پایگاه داده و کلید رمزنگاری را بررسی کنید.", 503, { "set-cookie": clearCookie });
  }
  return html("اتصال کافه‌بازار با موفقیت انجام شد. Refresh Token به‌صورت رمزگذاری‌شده در پایگاه داده ذخیره شد و در صفحه یا نشانی مرورگر نمایش داده نمی‌شود. اکنون می‌توانید وضعیت اتصال را بررسی کنید.", 200, { "set-cookie": clearCookie });
}

export async function handleBazaarOAuth(req, env, path) {
  try {
    if (path === "/v1/billing/bazaar/oauth/start") return await start(req, env);
    if (path === "/v1/billing/bazaar/oauth/callback") return await callback(req, env);
    return html("یافت نشد.", 404);
  } catch {
    return html("درخواست اتصال کامل نشد. تنظیمات سرور را بررسی کنید و دوباره تلاش کنید.", 503);
  }
}
