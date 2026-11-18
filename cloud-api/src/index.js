const H = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };
const HASH = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,40}$/;
const MAX_FEED_BYTES = 4 * 1024 * 1024;
const MAX_FEED_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
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
 if(p==="/v1/hash/reputation"&&req.method==="POST"){
   try{
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
