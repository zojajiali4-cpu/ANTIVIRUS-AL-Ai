const PORTAL_HTML = "<!doctype html>\n<html lang=\"fa\" dir=\"rtl\">\n<head>\n<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"theme-color\" content=\"#07111e\"><title>ANTIVIRUS AL AI — Billing</title>\n<style>\n:root{color-scheme:dark;--bg:#07111e;--panel:#101d2d;--raised:#17283c;--teal:#42d9cf;--blue:#71a3ff;--text:#f3f7fc;--muted:#9fb1c5;--line:#294057}\n*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% 0%,#173b4a 0,transparent 42%),var(--bg);color:var(--text);font:15px/1.7 system-ui,-apple-system,\"Segoe UI\",sans-serif}\nmain{max-width:1040px;margin:auto;padding:28px 20px 70px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{display:flex;align-items:center;gap:12px;font-weight:850;letter-spacing:.3px}.logo{width:44px;height:44px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(135deg,var(--teal),var(--blue));color:#07111e;font-size:24px}\nbutton,input,select{font:inherit}button{cursor:pointer;border:0;border-radius:13px;padding:12px 17px;background:var(--teal);color:#07111e;font-weight:800}button:disabled{opacity:.5;cursor:not-allowed}.ghost{background:#1b3046;color:var(--text);border:1px solid var(--line)}\n.hero{margin:42px 0 26px;max-width:720px}.eyebrow{color:var(--teal);font-size:12px;letter-spacing:1.5px;font-weight:800}.hero h1{font-size:clamp(30px,5vw,48px);line-height:1.2;margin:8px 0 12px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(225px,1fr));gap:15px}.plan{background:linear-gradient(155deg,#17283c,#101d2d);border:1px solid var(--line);border-radius:22px;padding:20px;display:flex;flex-direction:column;gap:13px;min-height:300px}.plan.featured{border-color:#42d9cf88;box-shadow:0 0 0 1px #42d9cf22}.plan h2{font-size:18px;margin:0}.price{font-size:22px;font-weight:850;color:var(--teal)}.features{margin:0;padding:0 18px;color:var(--muted);font-size:13px;flex:1}.plan button{width:100%}.checkout{display:none;margin-top:25px;padding:22px;background:var(--panel);border:1px solid var(--line);border-radius:22px}.checkout.show{display:block}.fields{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{display:flex;flex-direction:column;gap:6px}.field input,.field select{background:#0b1725;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px;min-width:0}.field.full{grid-column:1/-1}.routes{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}.route{background:#1b3046;color:var(--text);border:1px solid var(--line)}.route.active{border-color:var(--teal);color:var(--teal)}.notice{margin-top:15px;padding:12px 14px;border-radius:12px;background:#17283c;color:var(--muted);white-space:pre-wrap}.notice.error{color:#ff9ba2;border:1px solid #ff7e8644}.notice.good{color:#79ddb2;border:1px solid #79ddb244}.foot{margin-top:35px;padding-top:18px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}.lang{display:flex;gap:7px}\n@media(max-width:560px){main{padding:20px 14px 50px}.fields{grid-template-columns:1fr}.field.full{grid-column:auto}.hero{margin-top:30px}}\n</style></head>\n<body><main>\n<header class=\"top\"><div class=\"brand\"><span class=\"logo\">⬡</span><span>ANTIVIRUS AL AI<br><small class=\"muted\">SECURE MEMBERSHIP</small></span></div><div class=\"lang\"><button class=\"ghost\" id=\"lang\" type=\"button\">EN</button></div></header>\n<section class=\"hero\"><div class=\"eyebrow\" data-fa=\"مرکز رسمی خرید و اشتراک\" data-en=\"OFFICIAL MEMBERSHIP CENTER\">مرکز رسمی خرید و اشتراک</div><h1 data-fa=\"امنیت بیشتر، با کنترل کامل\" data-en=\"More protection. Full control.\">امنیت بیشتر، با کنترل کامل</h1><p class=\"muted\" data-fa=\"طرح مناسب را انتخاب کن. پرداخت داخلی و بین‌المللی در یک پنل مستقل مدیریت می‌شوند.\" data-en=\"Choose a plan. Domestic and international payments are managed through this independent portal.\">طرح مناسب را انتخاب کن. پرداخت داخلی و بین‌المللی در یک پنل مستقل مدیریت می‌شوند.</p></section>\n<section class=\"grid\" id=\"plans\">\n<article class=\"plan featured\"><div class=\"eyebrow\">PLUS</div><h2 data-fa=\"اشتراک ماهانه\" data-en=\"Monthly membership\">اشتراک ماهانه</h2><div class=\"price\" data-fa=\"قیمت در مرحله پرداخت\" data-en=\"Price at checkout\">قیمت در مرحله پرداخت</div><ul class=\"features\"><li data-fa=\"به‌روزرسانی بانک تهدید پس از عرضه\" data-en=\"Threat-feed updates when released\">به‌روزرسانی بانک تهدید پس از عرضه</li><li data-fa=\"اعتبارسنجی اختیاری هش\" data-en=\"Optional hash reputation\">اعتبارسنجی اختیاری هش</li><li data-fa=\"گزارش‌های امنیتی تکمیلی\" data-en=\"Expanded security reports\">گزارش‌های امنیتی تکمیلی</li></ul><button data-plan=\"PLUS_MONTHLY\" data-fa=\"انتخاب طرح\" data-en=\"Choose plan\">انتخاب طرح</button></article>\n<article class=\"plan\"><div class=\"eyebrow\">PLUS ANNUAL</div><h2 data-fa=\"اشتراک سالانه\" data-en=\"Annual membership\">اشتراک سالانه</h2><div class=\"price\" data-fa=\"قیمت در مرحله پرداخت\" data-en=\"Price at checkout\">قیمت در مرحله پرداخت</div><ul class=\"features\"><li data-fa=\"تمام امکانات PLUS\" data-en=\"Everything in PLUS\">تمام امکانات PLUS</li><li data-fa=\"مدیریت تمدید و اشتراک\" data-en=\"Subscription management\">مدیریت تمدید و اشتراک</li></ul><button class=\"ghost\" data-plan=\"PLUS_ANNUAL\" data-fa=\"انتخاب طرح\" data-en=\"Choose plan\">انتخاب طرح</button></article>\n<article class=\"plan\"><div class=\"eyebrow\">PRO FAMILY</div><h2 data-fa=\"خانوادگی\" data-en=\"Family plan\">خانوادگی</h2><div class=\"price\" data-fa=\"قیمت در مرحله پرداخت\" data-en=\"Price at checkout\">قیمت در مرحله پرداخت</div><ul class=\"features\"><li data-fa=\"مدیریت چند دستگاه با رضایت کاربران\" data-en=\"Multiple devices with user consent\">مدیریت چند دستگاه با رضایت کاربران</li><li data-fa=\"نمای کلی امنیت خانواده\" data-en=\"Family security overview\">نمای کلی امنیت خانواده</li></ul><button class=\"ghost\" data-plan=\"PRO_FAMILY\" data-fa=\"انتخاب طرح\" data-en=\"Choose plan\">انتخاب طرح</button></article>\n<article class=\"plan\"><div class=\"eyebrow\">LIFETIME</div><h2 data-fa=\"مجوز دائمی آفلاین\" data-en=\"Lifetime offline licence\">مجوز دائمی آفلاین</h2><div class=\"price\" data-fa=\"پرداخت یک‌باره\" data-en=\"One-time payment\">پرداخت یک‌باره</div><ul class=\"features\"><li data-fa=\"بدون تمدید اشتراک\" data-en=\"No recurring renewal\">بدون تمدید اشتراک</li><li data-fa=\"ابزارهای محلی طبق شرایط عرضه\" data-en=\"Local tools under release terms\">ابزارهای محلی طبق شرایط عرضه</li></ul><button class=\"ghost\" data-plan=\"LIFETIME_OFFLINE\" data-fa=\"انتخاب طرح\" data-en=\"Choose plan\">انتخاب طرح</button></article>\n</section>\n<section class=\"checkout\" id=\"checkout\"><div class=\"eyebrow\" data-fa=\"تکمیل سفارش\" data-en=\"CHECKOUT DETAILS\">تکمیل سفارش</div><h2 id=\"selected\">—</h2><div class=\"fields\"><label class=\"field full\"><span data-fa=\"ایمیل رسید و پیگیری\" data-en=\"Receipt and order email\">ایمیل رسید و پیگیری</span><input id=\"email\" type=\"email\" autocomplete=\"email\" maxlength=\"254\" placeholder=\"you@example.com\" required></label></div><div class=\"field\" style=\"margin-top:15px\"><span data-fa=\"روش پرداخت\" data-en=\"Payment route\">روش پرداخت</span><div class=\"routes\"><button type=\"button\" class=\"route active\" data-provider=\"zarinpal\">درگاه ایران · ریال</button><button type=\"button\" class=\"route\" data-provider=\"stripe\">International · USD</button></div></div><button id=\"pay\" type=\"button\" data-fa=\"ادامه به درگاه امن\" data-en=\"Continue to secure checkout\">ادامه به درگاه امن</button><div id=\"notice\" class=\"notice\" role=\"status\" aria-live=\"polite\"></div></section>\n<footer class=\"foot\"><p data-fa=\"پرداخت فقط پس از تأیید سمت سرور فعال می‌شود. اطلاعات کارت در این وب‌سایت ذخیره نمی‌شود. اسکنر آنتی‌ویروس فایل‌های شخصی را برای خرید یا فعال‌سازی آپلود نمی‌کند.\" data-en=\"A purchase is activated only after server-side payment verification. Card details are not stored on this website. The antivirus scanner never uploads personal files for checkout or activation.\">پرداخت فقط پس از تأیید سمت سرور فعال می‌شود. اطلاعات کارت در این وب‌سایت ذخیره نمی‌شود. اسکنر آنتی‌ویروس فایل‌های شخصی را برای خرید یا فعال‌سازی آپلود نمی‌کند.</p><p>© ANTIVIRUS AL AI</p></footer>\n</main>\n<script>\nconst API_BASE = window.ANTIVIRUS_BILLING_API || window.location.origin;\nlet locale=\"fa\", selectedPlan=\"\", provider=\"zarinpal\";\nconst checkout=document.querySelector(\"#checkout\"), notice=document.querySelector(\"#notice\");\nfunction msg(text,type=\"\"){notice.textContent=text;notice.className=\"notice \"+type}\nfunction applyLanguage(){document.documentElement.lang=locale;document.documentElement.dir=locale===\"fa\"?\"rtl\":\"ltr\";document.querySelector(\"#lang\").textContent=locale===\"fa\"?\"EN\":\"فا\";document.querySelectorAll(\"[data-fa][data-en]\").forEach(el=>el.textContent=el.dataset[locale])}\ndocument.querySelector(\"#lang\").addEventListener(\"click\",()=>{locale=locale===\"fa\"?\"en\":\"fa\";applyLanguage()});\ndocument.querySelectorAll(\"[data-plan]\").forEach(btn=>btn.addEventListener(\"click\",()=>{selectedPlan=btn.dataset.plan;document.querySelector(\"#selected\").textContent=selectedPlan.replaceAll(\"_\",\" \");checkout.classList.add(\"show\");checkout.scrollIntoView({behavior:\"smooth\",block:\"center\"});msg(locale===\"fa\"?\"ایمیل و درگاه پرداخت را انتخاب کن.\":\"Enter your email and choose a payment route.\")}));\ndocument.querySelectorAll(\"[data-provider]\").forEach(btn=>btn.addEventListener(\"click\",()=>{provider=btn.dataset.provider;document.querySelectorAll(\"[data-provider]\").forEach(x=>x.classList.toggle(\"active\",x===btn))}));\ndocument.querySelector(\"#pay\").addEventListener(\"click\",async()=>{const email=document.querySelector(\"#email\").value.trim();if(!selectedPlan||!email){msg(locale===\"fa\"?\"طرح و ایمیل معتبر را وارد کن.\":\"Choose a plan and enter a valid email.\",\"error\");return}if(!API_BASE){msg(locale===\"fa\"?\"پنل هنوز به نشانی API مستقرشده متصل نشده است. پرداخت واقعی غیرفعال است.\":\"The portal API has not been deployed and connected yet. Live payments are disabled.\",\"error\");return}\nconst button=document.querySelector(\"#pay\");button.disabled=true;msg(locale===\"fa\"?\"در حال ایجاد سفارش امن…\":\"Creating secure order…\");\ntry{const response=await fetch(API_BASE.replace(/\\/$/,\"\")+\"/api/checkout\",{method:\"POST\",headers:{\"content-type\":\"application/json\"},body:JSON.stringify({email,plan:selectedPlan,provider,locale})});const data=await response.json();if(!response.ok)throw new Error(data.error||\"Checkout failed\");if(!data.checkoutUrl)throw new Error(\"No checkout URL returned\");location.assign(data.checkoutUrl)}catch(error){msg(error.message||\"Checkout failed\",\"error\");button.disabled=false}});\nconst status=new URLSearchParams(location.search).get(\"payment\");if(status===\"success\")msg(locale===\"fa\"?\"پرداخت تأیید شد. وضعیت سفارش را از طریق پشتیبانی پیگیری کن.\":\"Payment verified. Keep your order reference for support.\",\"good\");else if(status===\"failed\"||status===\"cancelled\")msg(locale===\"fa\"?\"پرداخت تکمیل نشد. مبلغی فعال نشده است.\":\"Payment was not completed. No plan was activated.\",\"error\");else if(status===\"processing\")msg(locale===\"fa\"?\"در حال بررسی نتیجه پرداخت؛ چند لحظه دیگر وضعیت سفارش را بررسی کن.\":\"Payment is being confirmed. Check the order status shortly.\");\nconst requestedPlan=new URLSearchParams(location.search).get(\"plan\");if(requestedPlan&&document.querySelector(`[data-plan=\"${requestedPlan}\"]`))document.querySelector(`[data-plan=\"${requestedPlan}\"]`).click();\napplyLanguage();\n</script></body></html>\n";
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const PLAN_CODES = new Set(["PLUS_MONTHLY", "PLUS_ANNUAL", "PRO_FAMILY", "LIFETIME_OFFLINE"]);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function cors(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(v => v.trim()).filter(Boolean);
  const headers = { "Vary": "Origin" };
  if (origin === new URL(request.url).origin || allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Stripe-Signature";
    headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
  }
  return headers;
}
function validEmail(value) {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function nowIso() { return new Date().toISOString(); }
function addInterval(interval) {
  const d = new Date();
  if (interval === "month") d.setUTCMonth(d.getUTCMonth() + 1);
  else if (interval === "year") d.setUTCFullYear(d.getUTCFullYear() + 1);
  else return null;
  return d.toISOString();
}
async function readTextBounded(request, maxBytes) {
  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > maxBytes) throw new Error("Request too large");
  if (!request.body) throw new Error("Invalid JSON");

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("Request too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

async function readJson(request) {
  const raw = await readTextBounded(request, 12_000);
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("Invalid JSON");
  }
}

async function enforceBillingRateLimit(request, env, scope, limit) {
  if (!env.DB) throw new Error("DATABASE_UNAVAILABLE");
  const salt = typeof env.RATE_SALT === "string" ? env.RATE_SALT : "";
  const saltBytes = new TextEncoder().encode(salt);
  if (saltBytes.byteLength < 32) throw new Error("RATE_LIMIT_KEY_NOT_CONFIGURED");

  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 128) throw new Error("CLIENT_ADDRESS_UNAVAILABLE");
  const keyObject = await crypto.subtle.importKey(
    "raw",
    saltBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", keyObject, new TextEncoder().encode(ip));
  const ipHash = [...new Uint8Array(signature)].map(value => value.toString(16).padStart(2, "0")).join("");
  const bucket = Math.floor(Date.now() / 60_000);

  try {
    await env.DB.prepare(
      "INSERT INTO billing_rate_limits(ip_hash,bucket,scope,hits) VALUES(?,?,?,1) ON CONFLICT(ip_hash,bucket,scope) DO UPDATE SET hits=hits+1"
    ).bind(ipHash, bucket, scope).run();
    const row = await env.DB.prepare(
      "SELECT hits FROM billing_rate_limits WHERE ip_hash=? AND bucket=? AND scope=?"
    ).bind(ipHash, bucket, scope).first();
    if (bucket % 10 === 0) {
      await env.DB.prepare("DELETE FROM billing_rate_limits WHERE bucket < ?").bind(bucket - 120).run();
    }
    return (row?.hits || 0) <= limit;
  } catch {
    throw new Error("RATE_LIMIT_STORAGE_UNAVAILABLE");
  }
}
async function getPlan(env, code) {
  if (!PLAN_CODES.has(code)) return null;
  const row = await env.DB.prepare("SELECT code,name,interval FROM plans WHERE code=? AND active=1").bind(code).first();
  if (!row) return null;
  const map = {
    PLUS_MONTHLY: { IRR: env.PRICE_PLUS_MONTHLY_IRR, USD: env.PRICE_PLUS_MONTHLY_USD },
    PLUS_ANNUAL: { IRR: env.PRICE_PLUS_ANNUAL_IRR, USD: env.PRICE_PLUS_ANNUAL_USD },
    PRO_FAMILY: { IRR: env.PRICE_PRO_FAMILY_IRR, USD: env.PRICE_PRO_FAMILY_USD },
    LIFETIME_OFFLINE: { IRR: env.PRICE_LIFETIME_IRR, USD: env.PRICE_LIFETIME_USD }
  };
  return { ...row, prices: map[code] };
}
async function createOrder(request, env) {
  let body;
  try {
    body = await readJson(request);
  } catch (error) {
    return json({ error: error.message === "Request too large" ? "Request too large." : "Invalid request body." }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ error: "A JSON object is required." }, 400);
  }
  const email = String(body.email || "").trim().toLowerCase();
  const locale = body.locale === "en" ? "en" : "fa";
  const plan = await getPlan(env, body.plan);
  const provider = body.provider === "stripe" ? "stripe" : body.provider === "zarinpal" ? "zarinpal" : "";
  const currency = provider === "stripe" ? "USD" : "IRR";
  const amount = Number(plan?.prices?.[currency]);
  if (!validEmail(email)) return json({ error: "A valid email address is required." }, 400);
  if (!plan || !provider || !Number.isSafeInteger(amount) || amount < 1) {
    return json({ error: "This plan or payment route is not configured yet." }, 409);
  }
  if (provider === "stripe" && !env.STRIPE_SECRET_KEY) return json({ error: "International payments are not configured yet." }, 503);
  if (provider === "zarinpal" && !env.ZARINPAL_MERCHANT_ID) return json({ error: "Domestic payments are not configured yet." }, 503);

  const customerId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO customers(id,email,locale) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET locale=excluded.locale")
    .bind(customerId, email, locale).run();
  const customer = await env.DB.prepare("SELECT id FROM customers WHERE email=?").bind(email).first();
  const orderId = crypto.randomUUID();
  const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  await env.DB.prepare("INSERT INTO orders(id,customer_id,plan_code,provider,currency,amount,status,expires_at) VALUES(?,?,?,?,?,?,'pending',?)")
    .bind(orderId, customer.id, plan.code, provider, currency, amount, expires).run();

  const origin = new URL(request.url).origin;
  const callback = origin + "/api/payments/" + provider + "/callback?order=" + encodeURIComponent(orderId);
  let checkoutUrl = "";
  try {
    if (provider === "zarinpal") {
      const response = await fetch("https://payment.zarinpal.com/pg/v4/payment/request.json", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          merchant_id: env.ZARINPAL_MERCHANT_ID, amount, currency: "IRR",
          description: "ANTIVIRUS AL AI " + plan.name,
          callback_url: callback, metadata: { email, order_id: orderId }
        })
      });
      const result = await response.json();
      const data = result.data || {};
      if (!response.ok || !data.authority || !(data.code === 100 || data.code === 101)) throw new Error("Zarinpal request rejected");
      checkoutUrl = "https://payment.zarinpal.com/pg/StartPay/" + encodeURIComponent(data.authority);
      await env.DB.prepare("UPDATE orders SET authority=?,checkout_url=? WHERE id=?").bind(data.authority, checkoutUrl, orderId).run();
    } else {
      const params = new URLSearchParams();
      params.set("mode", "payment");
      params.set("success_url", callback + "&session_id={CHECKOUT_SESSION_ID}");
      params.set("cancel_url", (env.PORTAL_URL || origin) + "?payment=cancelled&order=" + orderId);
      params.set("customer_email", email);
      params.set("client_reference_id", orderId);
      params.set("metadata[order_id]", orderId);
      params.set("line_items[0][quantity]", "1");
      params.set("line_items[0][price_data][currency]", "usd");
      params.set("line_items[0][price_data][unit_amount]", String(amount));
      params.set("line_items[0][price_data][product_data][name]", "ANTIVIRUS AL AI " + plan.name);
      const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
        method: "POST", headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY, "content-type": "application/x-www-form-urlencoded" }, body: params
      });
      const session = await response.json();
      if (!response.ok || !session.url || !session.id) throw new Error("Stripe checkout could not be created");
      checkoutUrl = session.url;
      await env.DB.prepare("UPDATE orders SET provider_session_id=?,checkout_url=? WHERE id=?").bind(session.id, checkoutUrl, orderId).run();
    }
    return json({ orderId, checkoutUrl, provider, currency, amount });
  } catch (error) {
    await env.DB.prepare("UPDATE orders SET status='failed' WHERE id=?").bind(orderId).run();
    return json({ error: "Could not start checkout. Please try again later." }, 502);
  }
}
export async function activateOrder(env, orderId, providerReference) {
  const reference = String(providerReference || "").trim();
  if (!reference || reference.length > 256) return false;

  const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(orderId).first();
  if (!order) return false;

  if (order.status === "paid") {
    return order.provider_reference === reference;
  }
  const paidAt = nowIso();
  if (order.status !== "pending" || order.expires_at < paidAt) return false;

  const subscriptionId = crypto.randomUUID();
  const endsAt = order.plan_code === "LIFETIME_OFFLINE" ? null : addInterval(order.plan_code === "PLUS_MONTHLY" ? "month" : "year");

  // D1 batch is transactional. The order transition, provider reference and
  // subscription insert are one transaction. The unique order_id constraint
  // makes duplicate callbacks idempotent even when they arrive in the same ms.
  await env.DB.batch([
    env.DB.prepare("UPDATE orders SET status='paid',paid_at=?,provider_reference=? WHERE id=? AND status='pending' AND expires_at>=?")
      .bind(paidAt, reference, orderId, paidAt),
    env.DB.prepare("INSERT OR IGNORE INTO subscriptions(id,customer_id,plan_code,order_id,status,starts_at,ends_at) SELECT ?,?,?,?,'active',?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='paid' AND paid_at=? AND provider_reference=?)")
      .bind(subscriptionId, order.customer_id, order.plan_code, order.id, paidAt, endsAt, orderId, paidAt, reference)
  ]);

  // A concurrent callback may have won the transition. Treat it as idempotent
  // only when the exact same provider transaction reference was already saved.
  const finalOrder = await env.DB.prepare("SELECT status,provider_reference FROM orders WHERE id=?").bind(orderId).first();
  return finalOrder?.status === "paid" && finalOrder.provider_reference === reference;
}
async function zarinpalCallback(request, env, url) {
  const orderId = url.searchParams.get("order") || "";
  const status = url.searchParams.get("Status");
  const authority = url.searchParams.get("Authority");
  const order = await env.DB.prepare("SELECT * FROM orders WHERE id=? AND provider='zarinpal'").bind(orderId).first();
  if (!order || !authority || authority !== order.authority || status !== "OK") return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=failed", 303);
  const response = await fetch("https://payment.zarinpal.com/pg/v4/payment/verify.json", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ merchant_id: env.ZARINPAL_MERCHANT_ID, amount: order.amount, authority })
  });
  const result = await response.json();
  if (!response.ok || ![100, 101].includes(result.data?.code)) return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=failed", 303);
  await activateOrder(env, orderId, result.data.ref_id);
  return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=success&order=" + encodeURIComponent(orderId), 303);
}
function constantTimeHexEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

async function verifyStripeSignature(raw, header, secret) {
  let timestamp = "";
  const signatures = [];
  for (const part of header.split(",")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name === "t") timestamp = value;
    if (name === "v1" && /^[0-9a-f]{64}$/i.test(value)) signatures.push(value.toLowerCase());
  }
  if (!/^[0-9]{1,12}$/.test(timestamp) || signatures.length === 0 ||
      Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(timestamp + "." + raw));
  const expected = [...new Uint8Array(signed)].map(value => value.toString(16).padStart(2, "0")).join("");
  return signatures.some(signature => constantTimeHexEqual(expected, signature));
}
async function stripeWebhook(request, env) {
  let raw;
  try {
    raw = await readTextBounded(request, 128 * 1024);
  } catch {
    return json({ error: "Invalid webhook body" }, 400);
  }
  if (!env.STRIPE_WEBHOOK_SECRET || !await verifyStripeSignature(raw, request.headers.get("Stripe-Signature") || "", env.STRIPE_WEBHOOK_SECRET)) {
    return json({ error: "Invalid signature" }, 400);
  }
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    return json({ error: "Invalid webhook event JSON" }, 400);
  }
  if (event.type === "checkout.session.completed" && event.data?.object?.payment_status === "paid") {
    const session = event.data.object;
    const orderId = session.metadata?.order_id || session.client_reference_id;
    const order = await env.DB.prepare("SELECT id,provider_session_id,amount,currency FROM orders WHERE id=? AND provider='stripe'").bind(orderId).first();
    if (order && order.provider_session_id === session.id && order.amount === session.amount_total && order.currency.toLowerCase() === session.currency) {
      await activateOrder(env, orderId, session.payment_intent || session.id);
    }
  }
  return json({ received: true });
}
async function orderStatus(request, env) {
  let body;
  try {
    body = await readJson(request);
  } catch (error) {
    return json({ error: error.message === "Request too large" ? "Request too large." : "Invalid request body." }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ error: "A JSON object is required." }, 400);
  }
  const orderId = String(body.order || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(orderId) || !validEmail(email)) {
    return json({ error: "Order and email are required." }, 400);
  }
  const row = await env.DB.prepare("SELECT o.id,o.plan_code,o.status,o.currency,o.amount,o.created_at,o.paid_at,c.email FROM orders o JOIN customers c ON c.id=o.customer_id WHERE o.id=? AND c.email=?")
    .bind(orderId, email).first();
  if (!row) return json({ error: "Order not found." }, 404);
  return json({ order: { id: row.id, plan: row.plan_code, status: row.status, currency: row.currency, amount: row.amount, createdAt: row.created_at, paidAt: row.paid_at } });
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = cors(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (url.pathname === "/" && request.method === "GET") return new Response(PORTAL_HTML, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "x-frame-options": "DENY" } });
    if (url.pathname === "/api/health" && request.method === "GET") return json({ service: "antivirus-billing", status: "ok" }, 200, headers);
    if (url.pathname === "/api/plans" && request.method === "GET") {
      return json({ plans: [
        { code: "PLUS_MONTHLY", interval: "month" }, { code: "PLUS_ANNUAL", interval: "year" },
        { code: "PRO_FAMILY", interval: "year" }, { code: "LIFETIME_OFFLINE", interval: "once" }
      ] }, 200, headers);
    }
    if (url.pathname === "/api/checkout" && request.method === "POST") {
      if (headers["Access-Control-Allow-Origin"] === undefined && request.headers.get("Origin")) return json({ error: "Origin not allowed." }, 403, headers);
      try {
        if (!await enforceBillingRateLimit(request, env, "checkout", 10)) return json({ error: "Too many checkout attempts. Try again shortly." }, 429, headers);
      } catch {
        return json({ error: "Checkout service is temporarily unavailable." }, 503, headers);
      }
      const response = await createOrder(request, env);
      const payload = await response.json();
      return json(payload, response.status, headers);
    }
    if (url.pathname === "/api/order-status" && request.method === "POST") {
      if (headers["Access-Control-Allow-Origin"] === undefined && request.headers.get("Origin")) return json({ error: "Origin not allowed." }, 403, headers);
      try {
        if (!await enforceBillingRateLimit(request, env, "order-status", 30)) return json({ error: "Too many order-status requests. Try again shortly." }, 429, headers);
      } catch {
        return json({ error: "Order-status service is temporarily unavailable." }, 503, headers);
      }
      return orderStatus(request, env).then(r => new Response(r.body, { status: r.status, headers: { ...Object.fromEntries(r.headers), ...headers } }));
    }
    if (url.pathname === "/api/payments/zarinpal/callback" && request.method === "GET") return zarinpalCallback(request, env, url);
    if (url.pathname === "/api/payments/stripe/callback" && request.method === "GET") return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=processing", 303);
    if (url.pathname === "/api/webhooks/stripe" && request.method === "POST") return stripeWebhook(request, env);
    return json({ error: "Not found" }, 404, headers);
  }
};
