import { handleBazaarOAuth, readBazaarRefreshToken, storeBazaarRefreshToken } from "./bazaar-oauth.js";

const H = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };
const HASH = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,40}$/;
const MAX_FEED_BYTES = 4 * 1024 * 1024;
const MAX_FEED_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const PLUS_ACCESS_AUDIENCE = "antivirus-al-ai:hash-reputation";
const PLUS_ACCESS_TTL_SECONDS = 5 * 60;
const MAX_BAZAAR_RESPONSE_BYTES = 64 * 1024;
const BAZAAR_API_BASE = "https://pardakht.cafebazaar.ir";
const out = (v,s=200) => new Response(JSON.stringify(v),{status:s,headers:H});

function inspectUrl(value) {
 if(typeof value!=="string"||!value.length||value.length>2048||/[\s\x00-\x1f\x7f]/.test(value)) return {level:"INVALID",signals:["INVALID_INPUT"]};
 let u; try { u=new URL(value); } catch { return {level:"INVALID",signals:["MALFORMED_URL"]}; }
 if(!["http:","https:"].includes(u.protocol)) return {level:"INVALID",signals:["UNSUPPORTED_SCHEME"]};
 const host=u.hostname.toLowerCase().replace(/\.$/, ""), sig=[];
 if(u.username||u.password) sig.push("EMBEDDED_CREDENTIALS");
 if(host.split(".").some(x=>x.startsWith("xn--"))) sig.push("PUNYCODE_HOST");
 if(host.includes(":")||/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) sig.push("IP_LITERAL_HOST");
 if((host.match(/\./g)||[]).length>=4) sig.push("MANY_SUBDOMAINS");
 if(u.protocol==="http:") sig.push("UNENCRYPTED_HTTP");
 if(u.port&& !["80","443"].includes(u.port)) sig.push("UNUSUAL_PORT");
 if(["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly"].includes(host)) sig.push("URL_SHORTENER");
 const parts=(host+u.pathname+u.search).toLowerCase().split(/[^a-z0-9]+/);
 if(["login","verify","account","secure","wallet","password","support","update"].some(x=>parts.includes(x))) sig.push("SENSITIVE_KEYWORD");
 const level=sig.some(x=>["EMBEDDED_CREDENTIALS","IP_LITERAL_HOST","PUNYCODE_HOST"].includes(x))?"HIGH_RISK_STRUCTURE":sig.length?"CAUTION":"NO_STRUCTURAL_WARNING";
 return {level,signals:sig,normalizedUrl:u.origin+u.pathname+u.search};
}

async function limited(req,env){
 if(!env.DB) throw new Error("DATABASE_UNAVAILABLE");
 const salt = typeof env.RATE_SALT === "string" ? env.RATE_SALT : "";
 const saltBytes = new TextEncoder().encode(salt);
 if(saltBytes.byteLength < 32) throw new Error("RATE_LIMIT_KEY_NOT_CONFIGURED");
 const ip = req.headers.get("CF-Connecting-IP");
 if(!ip || ip.length > 128) throw new Error("CLIENT_ADDRESS_UNAVAILABLE");
 const keyObject = await crypto.subtle.importKey("raw",saltBytes,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const signature = await crypto.subtle.sign("HMAC",keyObject,new TextEncoder().encode(ip));
 const key = [...new Uint8Array(signature)].map(x=>x.toString(16).padStart(2,"0")).join("");
 const bucket = Math.floor(Date.now()/60000);
 try {
   await env.DB.prepare("INSERT INTO api_rate_limits(ip_hash,bucket,hits) VALUES(?,?,1) ON CONFLICT(ip_hash,bucket) DO UPDATE SET hits=hits+1").bind(key,bucket).run();
   const row = await env.DB.prepare("SELECT hits FROM api_rate_limits WHERE ip_hash=? AND bucket=?").bind(key,bucket).first();
   if(bucket%10===0) await env.DB.prepare("DELETE FROM api_rate_limits WHERE bucket < ?").bind(bucket-120).run();
   return (row?.hits||0)<=60;
 } catch { throw new Error("RATE_LIMIT_STORAGE_UNAVAILABLE"); }
}

async function body(req,max=65536){
 const rawLength=req.headers.get("content-length");
 if(rawLength!==null && Number.isFinite(Number(rawLength)) && Number(rawLength)>max) throw Error("BODY_TOO_LARGE");
 const reader=req.body?.getReader();
 if(!reader) return {};
 const chunks=[]; let total=0;
 try {
   while(true){
     const {done,value}=await reader.read();
     if(done) break;
     total+=value.byteLength;
     if(total>max){ await reader.cancel(); throw Error("BODY_TOO_LARGE"); }
     chunks.push(value);
   }
 } finally { reader.releaseLock(); }
 const bytes=new Uint8Array(total); let offset=0;
 for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 let text;
 try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}catch{throw Error("INVALID_UTF8");}
 return JSON.parse(text);
}

function decodeBase64(value){
 if(typeof value!=="string"||!value.length||value.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Error("INVALID_BASE64");
 const binary=atob(value), bytes=new Uint8Array(binary.length);
 for(let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
 return bytes;
}

function derLength(bytes,state){
 if(state.i>=bytes.length) throw Error("INVALID_DER_SIGNATURE");
 const first=bytes[state.i++];
 if(first<0x80) return first;
 const count=first&0x7f;
 if(count===0||count>2||state.i+count>bytes.length||bytes[state.i]===0) throw Error("INVALID_DER_SIGNATURE");
 let length=0;
 for(let n=0;n<count;n++) length=(length<<8)|bytes[state.i++];
 if(length<0x80) throw Error("INVALID_DER_SIGNATURE");
 return length;
}

function derEcdsaToRaw(der){
 const state={i:0};
 if(der[state.i++]!==0x30) throw Error("INVALID_DER_SIGNATURE");
 const sequenceLength=derLength(der,state);
 if(state.i+sequenceLength!==der.length) throw Error("INVALID_DER_SIGNATURE");
 const readInteger=()=>{
   if(der[state.i++]!==0x02) throw Error("INVALID_DER_SIGNATURE");
   const length=derLength(der,state), end=state.i+length;
   if(length<1||end>der.length) throw Error("INVALID_DER_SIGNATURE");
   let value=der.slice(state.i,end); state.i=end;
   if((value[0]&0x80)!==0) throw Error("INVALID_DER_SIGNATURE");
   if(value.length>1&&value[0]===0&&(value[1]&0x80)===0) throw Error("INVALID_DER_SIGNATURE");
   if(value[0]===0) value=value.slice(1);
   if(value.length>32) throw Error("INVALID_DER_SIGNATURE");
   const padded=new Uint8Array(32); padded.set(value,32-value.length); return padded;
 };
 const r=readInteger(), s=readInteger();
 if(state.i!==der.length) throw Error("INVALID_DER_SIGNATURE");
 const raw=new Uint8Array(64); raw.set(r,0); raw.set(s,32); return raw;
}

function bazaarMonthlySubscriptionId(env) {
  return env.BAZAAR_SUBSCRIPTION_MONTHLY_ID || env.BAZAAR_MONTHLY_PRODUCT_ID || "";
}

function bazaarAnnualSubscriptionId(env) {
  return env.BAZAAR_SUBSCRIPTION_ANNUAL_ID || env.BAZAAR_ANNUAL_PRODUCT_ID || "";
}

function isBazaarBillingConfigured(env) {
  const secret = typeof env.PLUS_ENTITLEMENT_HMAC_SECRET === "string"
    ? env.PLUS_ENTITLEMENT_HMAC_SECRET : "";
  const secretLength = new TextEncoder().encode(secret).byteLength;
  const monthlyId = bazaarMonthlySubscriptionId(env);
  const annualId = bazaarAnnualSubscriptionId(env);
  return Boolean(
    typeof env.BAZAAR_CLIENT_ID === "string" && env.BAZAAR_CLIENT_ID.trim() &&
    typeof env.BAZAAR_CLIENT_SECRET === "string" && env.BAZAAR_CLIENT_SECRET.trim() &&
    env.BAZAAR_PACKAGE_NAME === "com.antivirusalai" &&
    /^[A-Za-z0-9._-]{3,100}$/.test(monthlyId) &&
    /^[A-Za-z0-9._-]{3,100}$/.test(annualId) &&
    monthlyId !== annualId &&
    secretLength >= 32 && secretLength <= 4096
  );
}

function bazaarSubscriptionIds(env) {
  return [bazaarMonthlySubscriptionId(env), bazaarAnnualSubscriptionId(env)];
}

async function readBazaarJson(response) {
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BAZAAR_RESPONSE_BYTES) {
    throw Error("BAZAAR_RESPONSE_TOO_LARGE");
  }
  let value;
  try { value = JSON.parse(text); }
  catch { throw Error("BAZAAR_INVALID_JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw Error("BAZAAR_INVALID_RESPONSE");
  }
  return value;
}

async function fetchBazaarAccessToken(env) {
  if (!isBazaarBillingConfigured(env)) throw Error("BAZAAR_BILLING_NOT_CONFIGURED");
  const refreshToken = await readBazaarRefreshToken(env);
  const form = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: env.BAZAAR_CLIENT_ID,
    client_secret: env.BAZAAR_CLIENT_SECRET,
    refresh_token: refreshToken
  });
  let response;
  try {
    response = await fetch(BAZAAR_API_BASE + "/devapi/v2/auth/token/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "accept": "application/json" },
      body: form.toString(),
      redirect: "manual"
    });
  } catch {
    throw Error("BAZAAR_AUTH_UNAVAILABLE");
  }
  if (response.status === 400 || response.status === 401 || response.status === 403) {
    throw Error("BAZAAR_CREDENTIALS_REJECTED");
  }
  if (!response.ok) throw Error("BAZAAR_AUTH_UNAVAILABLE");
  const token = await readBazaarJson(response);
  if (typeof token.access_token !== "string" || !token.access_token.length ||
      token.access_token.length > 8192) throw Error("BAZAAR_TOKEN_RESPONSE_INVALID");
  if (typeof token.refresh_token === "string" && token.refresh_token.length &&
      token.refresh_token !== refreshToken) {
    await storeBazaarRefreshToken(env, token.refresh_token);
  }
  return token.access_token;
}

async function fetchBazaarSubscription(env, accessToken, subscriptionId, purchaseToken) {
  const path = "/devapi/v2/api/applications/" + encodeURIComponent(env.BAZAAR_PACKAGE_NAME) +
    "/subscriptions/" + encodeURIComponent(subscriptionId) +
    "/purchases/" + encodeURIComponent(purchaseToken) +
    "/?access_token=" + encodeURIComponent(accessToken);
  let response;
  try {
    response = await fetch(BAZAAR_API_BASE + path, {
      method: "GET",
      headers: { "accept": "application/json" },
      redirect: "manual"
    });
  } catch {
    throw Error("BAZAAR_PURCHASE_LOOKUP_UNAVAILABLE");
  }
  if (response.status === 400 || response.status === 401 ||
      response.status === 403 || response.status === 404) {
    throw Error("BAZAAR_PURCHASE_TOKEN_INVALID");
  }
  if (!response.ok) throw Error("BAZAAR_PURCHASE_LOOKUP_UNAVAILABLE");
  const result = await readBazaarJson(response);
  if (result.kind !== "androidpublisher#subscriptionPurchase") {
    throw Error("BAZAAR_SUBSCRIPTION_RESPONSE_INVALID");
  }
  const expiry = Number(result.validUntilTimestampMsec);
  if (!Number.isSafeInteger(expiry) || expiry <= 0) {
    throw Error("BAZAAR_SUBSCRIPTION_RESPONSE_INVALID");
  }
  return {
    expiresAtEpochMillis: expiry,
    autoRenewing: result.autoRenewing === true
  };
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value, maxBytes = 2048) {
  if (typeof value !== "string" || !value.length || value.length > 4096 ||
      !/^[A-Za-z0-9_-]+$/.test(value)) throw Error("PLUS_TOKEN_INVALID");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4);
  let binary;
  try { binary = atob(base64); } catch { throw Error("PLUS_TOKEN_INVALID"); }
  if (!binary.length || binary.length > maxBytes) throw Error("PLUS_TOKEN_INVALID");
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function issueBazaarPlusAccessToken(env, subscriptionId, expiresAtEpochMillis, nowSeconds) {
  if (!isBazaarBillingConfigured(env)) throw Error("BAZAAR_BILLING_NOT_CONFIGURED");
  const subscriptionExpiresAt = Math.floor(expiresAtEpochMillis / 1000);
  if (!Number.isSafeInteger(subscriptionExpiresAt) || subscriptionExpiresAt <= nowSeconds) {
    throw Error("BAZAAR_PURCHASE_NOT_ENTITLED");
  }
  const issuedAt = nowSeconds;
  const expiresAt = Math.min(issuedAt + PLUS_ACCESS_TTL_SECONDS, subscriptionExpiresAt);
  if (expiresAt <= issuedAt) throw Error("BAZAAR_PURCHASE_NOT_ENTITLED");
  const claims = {
    v: 1,
    aud: PLUS_ACCESS_AUDIENCE,
    productId: subscriptionId,
    packageName: env.BAZAAR_PACKAGE_NAME,
    iat: issuedAt,
    exp: expiresAt,
    subscriptionExpiresAt
  };
  const encodedClaims = encodeBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.PLUS_ENTITLEMENT_HMAC_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(encodedClaims));
  return encodedClaims + "." + encodeBase64Url(new Uint8Array(signature));
}

async function verifyBazaarPlusAccessToken(req, env, nowSeconds) {
  if (!isBazaarBillingConfigured(env)) throw Error("BAZAAR_BILLING_NOT_CONFIGURED");
  const authorization = req.headers.get("authorization") || "";
  const match = /^Bearer ([A-Za-z0-9_.-]{20,4096})$/.exec(authorization);
  if (!match) return false;
  const parts = match[1].split(".");
  if (parts.length !== 2) return false;
  let payloadBytes, signature;
  try {
    payloadBytes = decodeBase64Url(parts[0], 2048);
    signature = decodeBase64Url(parts[1], 64);
  } catch { return false; }
  if (signature.byteLength !== 32) return false;
  let claims;
  try {
    claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch { return false; }
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.PLUS_ENTITLEMENT_HMAC_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const signatureValid = await crypto.subtle.verify(
    "HMAC", key, signature, new TextEncoder().encode(parts[0])
  );
  if (!signatureValid) return false;
  const { v, aud, productId, packageName, iat, exp, subscriptionExpiresAt } = claims || {};
  const configuredProducts = bazaarSubscriptionIds(env);
  if (v !== 1 || aud !== PLUS_ACCESS_AUDIENCE ||
      !configuredProducts.includes(productId) ||
      packageName !== env.BAZAAR_PACKAGE_NAME ||
      !Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) ||
      !Number.isSafeInteger(subscriptionExpiresAt) ||
      iat > nowSeconds + 30 || exp <= nowSeconds || exp <= iat ||
      exp - iat > PLUS_ACCESS_TTL_SECONDS ||
      subscriptionExpiresAt <= nowSeconds || exp > subscriptionExpiresAt ||
      exp !== Math.min(iat + PLUS_ACCESS_TTL_SECONDS, subscriptionExpiresAt)) return false;
  return true;
}

async function verifyPublishedFeed(payloadText,env,now){
 if(typeof env.FEED_PUBLIC_KEY_B64!=="string"||typeof env.FEED_KEY_ID!=="string"||!KEY_ID.test(env.FEED_KEY_ID)){
   throw Error("FEED_VERIFICATION_NOT_CONFIGURED");
 }
 if(typeof payloadText!=="string"||!payloadText.length||new TextEncoder().encode(payloadText).byteLength>MAX_FEED_BYTES) throw Error("INVALID_FEED_SIZE");
 if(!payloadText.endsWith("\n")||payloadText.includes("\r")) throw Error("INVALID_FEED_FORMAT");
 const lines=payloadText.slice(0,-1).split("\n");
 if(lines.length<6) throw Error("INVALID_FEED_FORMAT");
 const signatureLine=lines.pop();
 if(!signatureLine.startsWith("signature=")) throw Error("INVALID_FEED_FORMAT");
 const header=lines;
 if(!["ALAI-THREAT-FEED/1","ALAI-THREAT-FEED/2"].includes(header[0])) throw Error("INVALID_FEED_FORMAT");
 const keyId=header[1]?.startsWith("key_id=")?header[1].slice(7):"";
 if(!KEY_ID.test(keyId)||keyId!==env.FEED_KEY_ID) throw Error("UNTRUSTED_FEED_KEY");
 const parsePositive=(line,prefix)=>{
   if(typeof line!=="string"||!line.startsWith(prefix)) throw Error("INVALID_FEED_FORMAT");
   const raw=line.slice(prefix.length);
   if(!/^[1-9][0-9]{0,15}$/.test(raw)) throw Error("INVALID_FEED_DATES");
   const value=Number(raw); if(!Number.isSafeInteger(value)) throw Error("INVALID_FEED_DATES"); return value;
 };
 const version=parsePositive(header[2],"version=");
 const issued=parsePositive(header[3],"issued_at=");
 const expires=parsePositive(header[4],"expires_at=");
 if(issued>now+300||expires<=now||expires<=issued||expires-issued>MAX_FEED_LIFETIME_SECONDS) throw Error("INVALID_FEED_DATES");
 const signature=decodeBase64(signatureLine.slice(10));
 const signedPayload=new TextEncoder().encode(header.join("\n")+"\n");
 const spki=decodeBase64(env.FEED_PUBLIC_KEY_B64);
 let publicKey;
 try{publicKey=await crypto.subtle.importKey("spki",spki,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);}
 catch{throw Error("FEED_PUBLIC_KEY_INVALID");}
 let valid=false;
 try{valid=await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},publicKey,derEcdsaToRaw(signature),signedPayload);}
 catch{valid=false;}
 if(!valid) throw Error("INVALID_FEED_SIGNATURE");
 return {version,issuedAt:issued,expiresAt:expires};
}

export default { async fetch(req,env){
 const u=new URL(req.url), p=u.pathname;
 if(req.method==="OPTIONS"){
   const origin=req.headers.get("Origin")||"";
   const allowed=(env.CORS_ALLOWED_ORIGINS||"").split(",").map(x=>x.trim()).filter(Boolean);
   const headers={...H,"access-control-allow-methods":"GET,POST,OPTIONS","access-control-allow-headers":"content-type,authorization","vary":"Origin"};
   if(origin&&allowed.includes(origin)) headers["access-control-allow-origin"]=origin;
   return new Response(null,{status:204,headers});
 }
 if(p==="/v1/health"&&req.method==="GET") return out({ok:true,service:"ANTIVIRUS AL AI API",version:"1.1.0",database:!!env.DB});
 if(!p.startsWith("/v1/")) return out({error:"NOT_FOUND"},404);
 try{if(!await limited(req,env)) return out({error:"RATE_LIMITED",retryAfterSeconds:60},429);}
 catch(error){
   const code=error?.message==="DATABASE_UNAVAILABLE"?"DATABASE_UNAVAILABLE":
     error?.message==="RATE_LIMIT_KEY_NOT_CONFIGURED"?"RATE_LIMIT_KEY_NOT_CONFIGURED":
     error?.message==="CLIENT_ADDRESS_UNAVAILABLE"?"CLIENT_ADDRESS_UNAVAILABLE":"RATE_LIMIT_STORAGE_UNAVAILABLE";
   return out({error:code},503);
 }
 if(p==="/v1/billing/bazaar/oauth/start" || p==="/v1/billing/bazaar/oauth/callback"){
   return handleBazaarOAuth(req,env,p);
 }
 if(p==="/v1/url/check"&&req.method==="POST"){
   try{
     const x=await body(req),a=inspectUrl(x.url);
     if(a.level==="INVALID") return out({ok:false,assessment:a},400);
     const host=new URL(x.url).hostname.toLowerCase().replace(/\.$/,"");
     a.reputation=await env.DB.prepare("SELECT classification,source,updated_at FROM url_reputation WHERE host=?").bind(host).first()||null;
     return out({ok:true,assessment:a,scope:"STRUCTURAL_ANALYSIS_AND_CURATED_REPUTATION",disclaimer:"No URL was opened or fetched. Structural checks are not proof of safety or maliciousness."});
   }catch(e){
     if(e.message==="BODY_TOO_LARGE") return out({error:"BODY_TOO_LARGE"},400);
     if(e.message==="INVALID_UTF8") return out({error:"INVALID_UTF8"},400);
     if(e instanceof SyntaxError) return out({error:"INVALID_JSON"},400);
     return out({error:"URL_REPUTATION_LOOKUP_UNAVAILABLE"},503);
   }
 }
 if(p==="/v1/billing/bazaar/status"&&req.method==="GET"){
   if(!isBazaarBillingConfigured(env)){
     return out({ok:true,checkoutReady:false,monthlySku:bazaarMonthlySubscriptionId(env)||null,
       annualSku:bazaarAnnualSubscriptionId(env)||null,reason:"NOT_CONFIGURED"});
   }
   try{
     await fetchBazaarAccessToken(env);
     return out({ok:true,checkoutReady:true,monthlySku:bazaarMonthlySubscriptionId(env),
       annualSku:bazaarAnnualSubscriptionId(env)});
   }catch(error){
     const code=error?.message||"";
     if(code==="BAZAAR_REFRESH_TOKEN_NOT_CONFIGURED"){
       return out({ok:true,checkoutReady:false,monthlySku:bazaarMonthlySubscriptionId(env),
         annualSku:bazaarAnnualSubscriptionId(env),reason:"AUTHORIZATION_REQUIRED"});
     }
     if(code==="BAZAAR_CREDENTIALS_REJECTED"){
       return out({ok:true,checkoutReady:false,monthlySku:bazaarMonthlySubscriptionId(env),
         annualSku:bazaarAnnualSubscriptionId(env),reason:"CREDENTIALS_REJECTED"});
     }
     return out({ok:false,checkoutReady:false,error:"BAZAAR_BILLING_UNAVAILABLE"},503);
   }
 }
 if(p==="/v1/billing/bazaar/verify"&&req.method==="POST"){
   try{
     const x=await body(req,16_384);
     const subscriptionId=typeof x.subscriptionId==="string"?x.subscriptionId:"";
     const purchaseToken=typeof x.purchaseToken==="string"?x.purchaseToken:"";
     if(!isBazaarBillingConfigured(env)) return out({error:"BAZAAR_BILLING_NOT_CONFIGURED"},503);
     if(!bazaarSubscriptionIds(env).includes(subscriptionId)) return out({error:"SUBSCRIPTION_NOT_ALLOWED"},400);
     if(purchaseToken.length<20||purchaseToken.length>4096||
        /[\s\x00-\x1f\x7f]/.test(purchaseToken)) return out({error:"PURCHASE_TOKEN_INVALID"},400);
     const nowSeconds=Math.floor(Date.now()/1000);
     const accessToken=await fetchBazaarAccessToken(env);
     const verified=await fetchBazaarSubscription(env,accessToken,subscriptionId,purchaseToken);
     if(verified.expiresAtEpochMillis<=Date.now()){
       return out({error:"PURCHASE_NOT_ENTITLED",entitled:false},403);
     }
     const tokenHash=await sha256Hex(purchaseToken);
     const nowMillis=Date.now();
     await env.DB.prepare(
       "INSERT INTO bazaar_subscription_verifications(purchase_token_sha256,subscription_id,expires_at,verified_at) VALUES(?,?,?,?) ON CONFLICT(purchase_token_sha256) DO UPDATE SET subscription_id=excluded.subscription_id,expires_at=excluded.expires_at,verified_at=excluded.verified_at"
     ).bind(tokenHash,subscriptionId,Math.floor(verified.expiresAtEpochMillis/1000),nowMillis).run();
     const cloudAccessToken=await issueBazaarPlusAccessToken(env,subscriptionId,verified.expiresAtEpochMillis,nowSeconds);
     return out({
       ok:true,entitled:true,subscriptionId,
       expiresAtEpochMillis:verified.expiresAtEpochMillis,
       autoRenewing:verified.autoRenewing,
       cloudAccessToken
     });
   }catch(error){
     const code=error?.message||"";
     if(code==="BODY_TOO_LARGE"||code==="INVALID_UTF8"||code==="INVALID_JSON") return out({error:code},400);
     if(code==="BAZAAR_PURCHASE_TOKEN_INVALID") return out({error:"PURCHASE_TOKEN_INVALID"},400);
     if(code==="BAZAAR_PURCHASE_NOT_ENTITLED") return out({error:"PURCHASE_NOT_ENTITLED",entitled:false},403);
     if(code==="BAZAAR_BILLING_NOT_CONFIGURED"||code==="BAZAAR_CREDENTIALS_REJECTED"||code==="BAZAAR_REFRESH_TOKEN_NOT_CONFIGURED") {
       return out({error:"BAZAAR_BILLING_NOT_CONFIGURED"},503);
     }
     if(code==="BAZAAR_RESPONSE_TOO_LARGE"||code==="BAZAAR_INVALID_JSON"||
        code==="BAZAAR_INVALID_RESPONSE"||code==="BAZAAR_SUBSCRIPTION_RESPONSE_INVALID") {
       return out({error:"BAZAAR_PURCHASE_RESPONSE_INVALID"},502);
     }
     return out({error:"BAZAAR_VERIFICATION_UNAVAILABLE"},503);
   }
 }
 if(p==="/v1/hash/reputation"&&req.method==="POST"){
   try{
     if(!isBazaarBillingConfigured(env)) return out({error:"BAZAAR_BILLING_NOT_CONFIGURED"},503);
     if(!await verifyBazaarPlusAccessToken(req,env,Math.floor(Date.now()/1000))) {
       return out({error:"PLUS_ENTITLEMENT_REQUIRED"},403);
     }
     const x=await body(req),h=typeof x.sha256==="string"?x.sha256.toLowerCase():"";
     if(!HASH.test(h)) return out({error:"INVALID_SHA256"},400);
     const r=await env.DB.prepare("SELECT classification,family_id,source,updated_at FROM hash_reputation WHERE sha256=?").bind(h).first();
     return out({ok:true,found:!!r,classification:r?.classification||"UNKNOWN",indicator:r||null,scope:"HASH_ONLY_REPUTATION",disclaimer:"Only the submitted SHA-256 digest was queried. A no-match is not proof of safety."});
   }catch(e){
     if(e.message==="BODY_TOO_LARGE") return out({error:"BODY_TOO_LARGE"},400);
     if(e.message==="INVALID_UTF8") return out({error:"INVALID_UTF8"},400);
     if(e instanceof SyntaxError) return out({error:"INVALID_JSON"},400);
     return out({error:"REPUTATION_LOOKUP_UNAVAILABLE"},503);
   }
 }
 if(p==="/v1/threat-feed/latest"&&req.method==="GET"){
   try{
     const r=await env.DB.prepare("SELECT version,expires_at,payload FROM signed_feeds ORDER BY version DESC LIMIT 1").first();
     if(!r) return out({error:"FEED_NOT_PUBLISHED"},404);
     if(r.expires_at<=Math.floor(Date.now()/1000)) return out({error:"FEED_EXPIRED"},410);
     return new Response(r.payload,{headers:{"content-type":"text/plain; charset=utf-8","cache-control":"public, max-age=300","x-feed-version":String(r.version)}});
   }catch{return out({error:"THREAT_FEED_STORAGE_UNAVAILABLE"},503);}
 }
 if(p==="/v1/admin/feed"&&req.method==="POST"){
   if(!env.ADMIN_API_KEY||req.headers.get("authorization")!=="Bearer "+env.ADMIN_API_KEY) return out({error:"UNAUTHORIZED"},401);
   try{
     const x=await body(req,MAX_FEED_BYTES+4096),t=x.payload;
     if(typeof t!=="string") return out({error:"INVALID_FEED"},400);
     const verified=await verifyPublishedFeed(t,env,Math.floor(Date.now()/1000));
     const old=await env.DB.prepare("SELECT MAX(version) AS v FROM signed_feeds").first();
     if(verified.version<=(old?.v||0)) return out({error:"VERSION_ROLLBACK"},409);
     await env.DB.prepare("INSERT INTO signed_feeds(version,issued_at,expires_at,payload) VALUES(?,?,?,?)").bind(verified.version,verified.issuedAt,verified.expiresAt,t).run();
     return out({ok:true,version:verified.version,signatureVerified:true});
   }catch(e){
     if(e.message==="BODY_TOO_LARGE") return out({error:"BODY_TOO_LARGE"},400);
     if(e.message==="INVALID_UTF8") return out({error:"INVALID_UTF8"},400);
     if(e.message==="INVALID_FEED_SIZE"||e.message==="INVALID_FEED_FORMAT"||e.message==="INVALID_FEED_DATES"||e.message==="INVALID_BASE64"||e.message==="INVALID_DER_SIGNATURE"||e.message==="INVALID_FEED_SIGNATURE"||e.message==="UNTRUSTED_FEED_KEY") return out({error:e.message},400);
     if(e.message==="FEED_VERIFICATION_NOT_CONFIGURED"||e.message==="FEED_PUBLIC_KEY_INVALID") return out({error:e.message},503);
     if(e instanceof SyntaxError) return out({error:"INVALID_JSON"},400);
     return out({error:"FEED_PUBLISH_STORAGE_UNAVAILABLE"},503);
   }
 }
 return out({error:"NOT_FOUND"},404);
}};
