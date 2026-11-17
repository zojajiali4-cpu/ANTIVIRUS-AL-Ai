const H = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };
const HASH = /^[a-f0-9]{64}$/;
const out = (v,s=200) => new Response(JSON.stringify(v),{status:s,headers:H});
function inspectUrl(value) {
 if(typeof value!=="string"||!value.length||value.length>2048||/[\\s\\x00-\\x1f\\x7f]/.test(value)) return {level:"INVALID",signals:["INVALID_INPUT"]};
 let u; try { u=new URL(value); } catch { return {level:"INVALID",signals:["MALFORMED_URL"]}; }
 if(!["http:","https:"].includes(u.protocol)) return {level:"INVALID",signals:["UNSUPPORTED_SCHEME"]};
 const host=u.hostname.toLowerCase().replace(/\\.$/,""), sig=[];
 if(u.username||u.password) sig.push("EMBEDDED_CREDENTIALS");
 if(host.split(".").some(x=>x.startsWith("xn--"))) sig.push("PUNYCODE_HOST");
 if(host.includes(":")||/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(host)) sig.push("IP_LITERAL_HOST");
 if((host.match(/\\./g)||[]).length>=4) sig.push("MANY_SUBDOMAINS");
 if(u.protocol==="http:") sig.push("UNENCRYPTED_HTTP");
 if(u.port&&!["80","443"].includes(u.port)) sig.push("UNUSUAL_PORT");
 if(["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly"].includes(host)) sig.push("URL_SHORTENER");
 const parts=(host+u.pathname+u.search).toLowerCase().split(/[^a-z0-9]+/);
 if(["login","verify","account","secure","wallet","password","support","update"].some(x=>parts.includes(x))) sig.push("SENSITIVE_KEYWORD");
 const level=sig.some(x=>["EMBEDDED_CREDENTIALS","IP_LITERAL_HOST","PUNYCODE_HOST"].includes(x))?"HIGH_RISK_STRUCTURE":sig.length?"CAUTION":"NO_STRUCTURAL_WARNING";
 return {level,signals:sig,normalizedUrl:u.origin+u.pathname+u.search};
}
async function limited(req,env){
 if(!env.DB)return true;
 const ip=req.headers.get("CF-Connecting-IP")||"unknown";
 const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(ip+(env.RATE_SALT||"alai-v1")));
 const key=[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join(""), bucket=Math.floor(Date.now()/60000);
 await env.DB.prepare("INSERT INTO api_rate_limits(ip_hash,bucket,hits) VALUES(?,?,1) ON CONFLICT(ip_hash,bucket) DO UPDATE SET hits=hits+1").bind(key,bucket).run();
 const row=await env.DB.prepare("SELECT hits FROM api_rate_limits WHERE ip_hash=? AND bucket=?").bind(key,bucket).first();
 if(bucket%10===0) await env.DB.prepare("DELETE FROM api_rate_limits WHERE bucket < ?").bind(bucket-120).run();
 return (row?.hits||0)<=60;
}
async function body(req,max=65536){const n=Number(req.headers.get("content-length")||0);if(n>max)throw Error("BODY_TOO_LARGE");const t=await req.text();if(t.length>max)throw Error("BODY_TOO_LARGE");return JSON.parse(t);}
export default { async fetch(req,env){
 const u=new URL(req.url), p=u.pathname;
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:{...H,"access-control-allow-origin":"*","access-control-allow-methods":"GET,POST,OPTIONS","access-control-allow-headers":"content-type,authorization"}});
 if(p==="/v1/health"&&req.method==="GET")return out({ok:true,service:"ANTIVIRUS AL AI API",version:"1.0.0",database:!!env.DB});
 if(!p.startsWith("/v1/"))return out({error:"NOT_FOUND"},404);
 if(!await limited(req,env))return out({error:"RATE_LIMITED",retryAfterSeconds:60},429);
 if(p==="/v1/url/check"&&req.method==="POST"){try{const x=await body(req),a=inspectUrl(x.url);if(a.level==="INVALID")return out({ok:false,assessment:a},400);if(env.DB){const host=new URL(x.url).hostname.toLowerCase();a.reputation=await env.DB.prepare("SELECT classification,source,updated_at FROM url_reputation WHERE host=?").bind(host).first()||null;}return out({ok:true,assessment:a,scope:"STRUCTURAL_ANALYSIS_AND_CURATED_REPUTATION",disclaimer:"No URL was opened or fetched. Structural checks are not proof of safety or maliciousness."});}catch(e){return out({error:e.message==="BODY_TOO_LARGE"?"BODY_TOO_LARGE":"INVALID_JSON"},400);}}
 if(p==="/v1/hash/reputation"&&req.method==="POST"){try{const x=await body(req),h=typeof x.sha256==="string"?x.sha256.toLowerCase():"";if(!HASH.test(h))return out({error:"INVALID_SHA256"},400);if(!env.DB)return out({ok:true,found:false,classification:"UNKNOWN"});const r=await env.DB.prepare("SELECT classification,family_id,source,updated_at FROM hash_reputation WHERE sha256=?").bind(h).first();return out({ok:true,found:!!r,classification:r?.classification||"UNKNOWN",indicator:r||null});}catch{return out({error:"INVALID_REQUEST"},400);}}
 if(p==="/v1/threat-feed/latest"&&req.method==="GET"){if(!env.DB)return out({error:"DATABASE_UNAVAILABLE"},503);const r=await env.DB.prepare("SELECT version,expires_at,payload FROM signed_feeds ORDER BY version DESC LIMIT 1").first();if(!r)return out({error:"FEED_NOT_PUBLISHED"},404);if(r.expires_at<=Math.floor(Date.now()/1000))return out({error:"FEED_EXPIRED"},410);return new Response(r.payload,{headers:{"content-type":"text/plain; charset=utf-8","cache-control":"public, max-age=300","x-feed-version":String(r.version)}});}
 if(p==="/v1/admin/feed"&&req.method==="POST"){if(!env.ADMIN_API_KEY||req.headers.get("authorization")!=="Bearer "+env.ADMIN_API_KEY)return out({error:"UNAUTHORIZED"},401);try{const x=await body(req,2*1024*1024),t=x.payload;if(typeof t!=="string"||t.length>2*1024*1024)return out({error:"INVALID_FEED"},400);const l=t.split("\
");if(l[0]!=="ALAI-THREAT-FEED/1"||!l[1]?.startsWith("key_id=")||!/^version=[1-9][0-9]*$/.test(l[2]||"")||!/^issued_at=[1-9][0-9]*$/.test(l[3]||"")||!/^expires_at=[1-9][0-9]*$/.test(l[4]||"")||!/^signature=[A-Za-z0-9+/]+=*$/.test(l[l.length-2]||""))return out({error:"INVALID_FEED_FORMAT"},400);const v=Number(l[2].slice(8)),i=Number(l[3].slice(10)),e=Number(l[4].slice(10)),now=Math.floor(Date.now()/1000);if(!Number.isSafeInteger(v)||!Number.isSafeInteger(i)||!Number.isSafeInteger(e)||e<=now||e<=i||e-i>2592000)return out({error:"INVALID_FEED_DATES"},400);const old=await env.DB.prepare("SELECT MAX(version) AS v FROM signed_feeds").first();if(v<=(old?.v||0))return out({error:"VERSION_ROLLBACK"},409);await env.DB.prepare("INSERT INTO signed_feeds(version,issued_at,expires_at,payload) VALUES(?,?,?,?)").bind(v,i,e,t).run();return out({ok:true,version:v});}catch{return out({error:"INVALID_REQUEST"},400);}}
 return out({error:"NOT_FOUND"},404);
}};