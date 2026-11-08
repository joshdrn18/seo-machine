import { DurableObject } from "cloudflare:workers";
const reply = (data, status, headers) => new Response(JSON.stringify(data), {status:status || 200,headers:Object.assign({"content-type":"application/json; charset=utf-8","cache-control":"no-store"},headers || {})});
function blocked(host) {
  const h=host.toLowerCase();
  if(h==="localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if(/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(h)) {
    const p=h.split(".").map(Number);
    if(p.some(n=>n>255)) return true;
    return p[0]===10 || p[0]===127 || p[0]===0 || p[0]>=224 || (p[0]===169&&p[1]===254) || (p[0]===172&&p[1]>=16&&p[1]<=31) || (p[0]===192&&p[1]===168);
  }
  return h.includes(":") || !h.includes(".") || !/^[a-z0-9.-]+$/.test(h);
}
function parseUrl(value) {
  let u; try { u=new URL(value); } catch(e) { throw new Error("Enter a valid website URL."); }
  if(u.protocol!=="https:"&&u.protocol!=="http:") throw new Error("Only HTTP and HTTPS websites are supported.");
  if(u.username||u.password||blocked(u.hostname)) throw new Error("This host is not allowed.");
  return u;
}
function extract(html, regex) { const m=regex.exec(html); return m ? m[1].replace(/<[^>]*>/g," ").replace(/&amp;/gi,"&").replace(/&nbsp;/gi," ").replace(/&quot;/gi,'"').replace(/&#39;/gi,"'").replace(/\s+/g," ").trim() : ""; }
function attr(tag,name){const m=tag.match(new RegExp("\\b"+name+"\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))","i"));return m?(m[1]??m[2]??m[3]??"").trim():"";}
function analyze(html,url,status,headers,extras={}) {
  const title=extract(html,/<title[^>]*>([\\s\\S]*?)<\\/title>/i);
  const description=extract(html,/<meta\\b(?=[^>]*name=["']description["'])(?=[^>]*content=["']([^"']*)["'])[^>]*>/i) || extract(html,/<meta\\b(?=[^>]*content=["']([^"']*)["'])(?=[^>]*name=["']description["'])[^>]*>/i);
  const canonicalTag=(html.match(/<link\\b[^>]*>/gi)||[]).find(tag=>/(^|\\s)canonical(\\s|$)/i.test(attr(tag,"rel")));
  const canonicalHref=canonicalTag?attr(canonicalTag,"href"):"";
  let canonicalValid=false,canonicalDetails="No canonical link element was detected.";
  if(canonicalHref){try{const canonicalUrl=new URL(canonicalHref,url);canonicalValid=canonicalUrl.protocol==="https:"||canonicalUrl.protocol==="http:";canonicalDetails="Canonical points to "+canonicalUrl.href+(canonicalUrl.origin!==url.origin?" (different origin).":"");}catch{canonicalDetails="Canonical href is not a valid URL: "+canonicalHref;}}
  const h1=(html.match(/<h1\\b/gi)||[]).length, headings=(html.match(/<h[1-6]\\b/gi)||[]).length;
  const imgs=html.match(/<img\\b[^>]*>/gi)||[], missing=imgs.filter(x=>! /\\balt\\s*=/.test(x)).length;
  const viewport=/<meta\\b(?=[^>]*name=["']viewport["'])/i.test(html);
  const robotsMeta=(html.match(/<meta\\b[^>]*>/gi)||[]).find(tag=>/^(robots|googlebot)$/i.test(attr(tag,"name")));
  const robots=robotsMeta?attr(robotsMeta,"content"):"";
  const xRobots=headers.get("x-robots-tag")||"";
  const robotsCombined=[robots,xRobots].filter(Boolean).join("; ");
  const jsonLd=(html.match(/<script\\b[^>]*type=["']application\\/ld\\+json["'][^>]*>[\\s\\S]*?<\\/script>/gi)||[]);
  let jsonLdValid=0,jsonLdInvalid=0;
  for(const block of jsonLd){const raw=block.replace(/^<script\\b[^>]*>/i,"").replace(/<\\/script>\\s*$/i,"").trim();try{JSON.parse(raw);jsonLdValid++;}catch{jsonLdInvalid++;}}
  const findings=[];
  function add(category,severity,titleText,details,recommendation){findings.push({category:category,severity:severity,title:titleText,details:details,recommendation:recommendation});}
  add("Technical",status>=200&&status<400?"passed":"critical","HTTP response","The page returned HTTP "+status+".","Keep the page reachable and return a successful status code.");
  add("On-page",!title?"critical":title.length>=30&&title.length<=60?"passed":"warning","Title tag",title?"Found a "+title.length+"-character title: "+title.slice(0,100):"No title tag was detected.","Add a unique, descriptive title; aim for roughly 30–60 characters.");
  add("On-page",!description?"critical":description.length>=70&&description.length<=160?"passed":"warning","Meta description",description?"Found a "+description.length+"-character description.":"No meta description was detected.","Write a compelling page-specific description of roughly 70–160 characters.");
  add("On-page",h1===1?"passed":"warning","H1 heading","Found "+h1+" H1 heading(s).","Use one clear primary H1 that describes the page.");
  add("On-page",headings>0?"passed":"warning","Heading structure","Detected "+headings+" heading elements.","Organize content with descriptive, logically nested headings.");
  add("Technical",!canonicalHref?"warning":canonicalValid?"passed":"critical","Canonical URL",canonicalDetails,"Set one valid, absolute canonical URL that points to the preferred indexable page.");
  add("Technical",viewport?"passed":"warning","Mobile viewport",viewport?"A viewport meta tag was found.":"No viewport meta tag was detected.","Add a responsive viewport meta tag for mobile browsers.");
  add("Images",missing===0?"passed":"warning","Image alternative text",missing+" of "+imgs.length+" images appear to be missing an alt attribute.","Add useful alt text to informative images and empty alt text to decorative images.");
  add("Technical",/noindex|none/i.test(robotsCombined)?"critical":"passed","Robots directives",robotsCombined?"Robots directives: "+robotsCombined:"No noindex directive was detected in the page meta or X-Robots-Tag header.","Confirm that noindex is intentional; remove it from pages that should appear in search.");
  add("Technical",url.protocol==="https:"?"passed":"critical","HTTPS",url.protocol==="https:"?"The URL uses HTTPS.":"The URL uses HTTP.","Serve the site over HTTPS and redirect HTTP to HTTPS.");
  add("Technical",(headers.get("content-type")||"").toLowerCase().includes("text/html")?"passed":"warning","HTML content type","Content-Type: "+(headers.get("content-type")||"not provided")+".","Serve HTML documents with a text/html content type.");
  add("Structured data",jsonLdInvalid?"warning":jsonLdValid?"passed":"warning","JSON-LD structured data",jsonLd.length?jsonLdValid+" valid JSON-LD block(s), "+jsonLdInvalid+" invalid block(s) detected.":"No JSON-LD structured data block was detected.","Add valid Schema.org JSON-LD where relevant, and validate each block before publishing.");
  const robotsCheck=extras.robots||{status:0,ok:false,missing:true};
  add("Crawlability",robotsCheck.ok?"passed":robotsCheck.missing?"passed":"warning","robots.txt",robotsCheck.ok?"robots.txt returned HTTP "+robotsCheck.status+".":robotsCheck.missing?"No robots.txt file was found; crawlers can still crawl by default.":"robots.txt check returned HTTP "+robotsCheck.status+".","Keep robots.txt reachable and ensure it does not block important pages or assets.");
  const mapCheck=extras.sitemap||{status:0,ok:false,missing:true,count:0};
  add("Indexing",mapCheck.ok&&mapCheck.count>0?"passed":mapCheck.missing?"warning":mapCheck.ok?"warning":"warning","XML sitemap",mapCheck.ok?"Sitemap returned HTTP "+mapCheck.status+" and contains "+mapCheck.count+" URL/location entries.":mapCheck.missing?"No sitemap was found at the advertised or default location.":"Sitemap check returned HTTP "+mapCheck.status+".","Publish a valid XML sitemap, include canonical indexable URLs, and submit its URL in Google Search Console.");
  const passed=findings.filter(f=>f.severity==="passed").length, warnings=findings.filter(f=>f.severity==="warning").length, critical=findings.filter(f=>f.severity==="critical").length;
  const score=Math.max(0,Math.round(findings.reduce((n,f)=>n+(f.severity==="passed"?10:f.severity==="warning"?5:0),0)/findings.length*10));
  return {url:url.href,hostname:url.hostname,status:status,title:title,description:description,score:score,findings:findings,summary:{passed:passed,warnings:warnings,critical:critical,total:findings.length},checkedAt:new Date().toISOString(),technical:{canonical:canonicalHref||null,robots:robotsCombined||null,jsonLdValid,jsonLdInvalid,sitemapUrls:mapCheck.count||0}};
}
async function fetchAuditText(url,maxBytes=262144,timeoutMs=5000){
  let response;
  try{response=await fetch(url.href,{redirect:"manual",signal:AbortSignal.timeout(timeoutMs),headers:{"user-agent":"SEOMachineBot/1.1","accept":"text/plain,application/xml,text/xml,*/*"}});}
  catch{return {ok:false,status:0,missing:false,text:""};}
  if(response.status===404||response.status===410)return {ok:false,status:response.status,missing:true,text:""};
  if(!response.ok||[301,302,303,307,308].includes(response.status))return {ok:false,status:response.status,missing:false,text:""};
  const reader=response.body?.getReader();let textBody="",size=0;
  if(reader){const decoder=new TextDecoder();while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>maxBytes){await reader.cancel();return {ok:false,status:response.status,missing:false,text:""};}textBody+=decoder.decode(part.value,{stream:true});}textBody+=decoder.decode();}
  return {ok:true,status:response.status,missing:false,text:textBody};
}
async function inspectCrawlFiles(target){
  const origin=new URL(target.origin);
  const robotsUrl=new URL("/robots.txt",origin);
  const robots=await fetchAuditText(robotsUrl,262144,5000);
  let sitemapUrl=null;
  if(robots.ok){const declared=robots.text.match(/^\\s*Sitemap:\\s*(\\S+)/im);if(declared){try{const parsed=new URL(declared[1],origin);if(parsed.origin===origin.origin&&parsed.protocol==="https:")sitemapUrl=parsed;}catch{}}}
  if(!sitemapUrl)sitemapUrl=new URL("/sitemap.xml",origin);
  const sitemap=await fetchAuditText(sitemapUrl,524288,6000);
  if(sitemap.ok){const locs=sitemap.text.match(/<(?:url|sitemap)\\b[^>]*>/gi)||[];sitemap.count=locs.length;}
  return {robots,sitemap};
}
async function doAudit(request,env,user) {
  const body=await request.json().catch(()=>null);
  if(!body||typeof body.url!=="string"||body.url.length>2048) return reply({error:"Provide a website URL."},400);
  let target; try { target=parseUrl(body.url); } catch(e) { return reply({error:e.message},400); }
  let response;
  try {
    response=await fetch(target.href,{redirect:"manual",signal:AbortSignal.timeout(12000),headers:{"user-agent":"SEOMachineBot/1.0","accept":"text/html,application/xhtml+xml"}});
    if([301,302,303,307,308].includes(response.status)) {
      const location=response.headers.get("location");
      if(!location) return reply({error:"Redirect did not include a destination."},422);
      const next=parseUrl(new URL(location,target).href);
      if(next.hostname!==target.hostname) return reply({error:"Cross-domain redirects are not followed. Audit the destination URL directly."},422);
      target=next;
      response=await fetch(target.href,{redirect:"manual",signal:AbortSignal.timeout(12000),headers:{"user-agent":"SEOMachineBot/1.0","accept":"text/html,application/xhtml+xml"}});
    }
  } catch(e) { return reply({error:"Could not fetch this website or the request timed out."},502); }
  if(!(response.headers.get("content-type")||"").includes("text/html")) return reply({error:"The URL did not return an HTML page."},422);
  const reader=response.body&&response.body.getReader(); let html="",size=0;
  if(reader) { const decoder=new TextDecoder(); while(true) { const part=await reader.read(); if(part.done) break; size+=part.value.byteLength; if(size>1048576) { await reader.cancel(); return reply({error:"Page exceeds the 1 MB audit limit."},413); } html+=decoder.decode(part.value,{stream:true}); } }
  const crawlFiles=await inspectCrawlFiles(target);\n  const audit=analyze(html,target,response.status,response.headers,crawlFiles);
  audit.ownerId=user.id; audit.ownerEmail=user.email;
  audit.id=crypto.randomUUID();
  try { await env.AUDITS.put("audit:"+audit.checkedAt+":"+audit.id,JSON.stringify(audit),{expirationTtl:2592000}); } catch(e) { return reply({error:"Audit completed but could not be saved. Please retry."},503); }
  return reply({audit:audit});
}

export class AuthDirectory extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS accounts (
          id TEXT PRIMARY KEY,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          name TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('super_admin','member')),
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE TABLE IF NOT EXISTS activity (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT,
          action TEXT NOT NULL,
          detail TEXT,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_activity_created ON activity(created_at DESC);
      `);
    });
  }
  countAccounts() {
    return this.ctx.storage.sql.exec("SELECT COUNT(*) AS total FROM accounts").one().total;
  }
  findByEmail(email) {
    return this.ctx.storage.sql.exec("SELECT id,email,name,role,status,password_hash,password_salt,created_at FROM accounts WHERE email = ? COLLATE NOCASE", email).toArray()[0] || null;
  }
  createFirstAdmin(user) {
    if (this.countAccounts() !== 0) return { created: false };
    this.ctx.storage.sql.exec("INSERT INTO accounts (id,email,name,role,status,password_hash,password_salt,created_at,updated_at) VALUES (?,?,?,'super_admin','active',?,?,?,?)", user.id,user.email,user.name,user.passwordHash,user.passwordSalt,user.createdAt,user.createdAt);
    this.addActivity(user.id,"account.bootstrap","Initial Super Admin account created");
    return { created: true };
  }
  createMember(user) {
    this.ctx.storage.sql.exec("INSERT INTO accounts (id,email,name,role,status,password_hash,password_salt,created_at,updated_at) VALUES (?,?,?,'member','active',?,?,?,?)", user.id,user.email,user.name,user.passwordHash,user.passwordSalt,user.createdAt,user.createdAt);
    this.addActivity(user.id,"account.created","Member account created");
    return { created: true };
  }
  createSession(session) {
    this.ctx.storage.sql.exec("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)",session.tokenHash,session.userId,session.expiresAt,session.createdAt);
  }
  getSession(tokenHash) {
    const row = this.ctx.storage.sql.exec("SELECT s.expires_at,a.id,a.email,a.name,a.role,a.status FROM sessions s JOIN accounts a ON a.id=s.user_id WHERE s.token_hash=?",tokenHash).toArray()[0] || null;
    if (!row || row.expires_at < Date.now() || row.status !== "active") {
      if (row) this.ctx.storage.sql.exec("DELETE FROM sessions WHERE token_hash=?",tokenHash);
      return null;
    }
    return {id:row.id,email:row.email,name:row.name,role:row.role,status:row.status,expiresAt:row.expires_at};
  }
  revokeSession(tokenHash) {
    this.ctx.storage.sql.exec("DELETE FROM sessions WHERE token_hash=?",tokenHash);
  }
  addActivity(userId,action,detail) {
    this.ctx.storage.sql.exec("INSERT INTO activity (user_id,action,detail,created_at) VALUES (?,?,?,?)",userId || null,action,detail || "",new Date().toISOString());
  }
  setUserStatus(id,status) {
    if(!["active","suspended"].includes(status)) throw new Error("Invalid account status");
    const result=this.ctx.storage.sql.exec("UPDATE accounts SET status=?,updated_at=? WHERE id=? AND role='member'",status,new Date().toISOString(),id);
    if(result.rowsWritten!==1) return false;
    this.addActivity(id,status==="active"?"account.reactivated":"account.suspended",status==="active"?"Member account reactivated by Super Admin":"Member account suspended by Super Admin");
    return true;
  }
  resetMemberPassword(id,passwordHash,passwordSalt) {
    const result=this.ctx.storage.sql.exec("UPDATE accounts SET password_hash=?,password_salt=?,updated_at=? WHERE id=? AND role='member'",passwordHash,passwordSalt,new Date().toISOString(),id);
    if(result.rowsWritten!==1) return false;
    this.ctx.storage.sql.exec("DELETE FROM sessions WHERE user_id=?",id);
    this.addActivity(id,"account.password_reset","Password reset by Super Admin; all sessions revoked");
    return true;
  }
  listUsers() {
    return this.ctx.storage.sql.exec("SELECT id,email,name,role,status,created_at FROM accounts ORDER BY created_at DESC").toArray();
  }
  listActivity(limit=100) {
    return this.ctx.storage.sql.exec("SELECT x.id,x.user_id,x.action,x.detail,x.created_at,a.email,a.name,a.role FROM activity x LEFT JOIN accounts a ON a.id=x.user_id ORDER BY x.id DESC LIMIT ?",Math.min(Math.max(Number(limit)||100,1),200)).toArray();
  }
}

export default {
  async fetch(request,env) {
    // This API uses explicit bearer session tokens, never browser cookies.
    // A wildcard CORS policy avoids Pages preview/custom-domain origin mismatches.
    const headers={
      "access-control-allow-origin":"*",
      "access-control-allow-methods":"GET, POST, PATCH, DELETE, OPTIONS",
      "access-control-allow-headers":"content-type,authorization",
      "access-control-max-age":"86400"
    };
    try {
    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:headers});
    const path=new URL(request.url).pathname;

    const auth = env.AUTH.getByName("account-directory");
    const readBody = async () => request.json().catch(()=>null);
    const hashText = async value => {
      const bytes = new TextEncoder().encode(value);
      const digest = await crypto.subtle.digest("SHA-256",bytes);
      return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
    };
    const passwordHash = async (password,salt) => {
      const key = await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:new TextEncoder().encode(salt),iterations:100000},key,256);
      return Array.from(new Uint8Array(bits),b=>b.toString(16).padStart(2,"0")).join("");
    };
    const getUser = async () => {
      const authHeader=request.headers.get("Authorization")||"";
      const token=authHeader.startsWith("Bearer ")?authHeader.slice(7):"";
      if(!token) return null;
      return auth.getSession(await hashText(token));
    };
    const event = async (userId,action,detail) => auth.addActivity(userId,action,detail);
    if(path==="/api/auth/status"&&request.method==="GET") return reply({ok:true,setupRequired:(await auth.countAccounts())===0},200,headers);
    if(path==="/api/auth/bootstrap"&&request.method==="POST") {
      const body=await readBody();
      if(!body || typeof body.email!=="string" || typeof body.password!=="string" || body.password.length<12 || body.password.length>128 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email) || body.email.length>254) return reply({error:"Enter a valid email and a password of at least 12 characters."},400,headers);
      const salt=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");
      const now=new Date().toISOString();
      const user={id:crypto.randomUUID(),email:body.email.trim().toLowerCase(),name:String(body.name||"Super Admin").trim().slice(0,80)||"Super Admin",passwordSalt:salt,passwordHash:await passwordHash(body.password,salt),createdAt:now};
      try { const result=await auth.createFirstAdmin(user); if(!result.created) return reply({error:"Initial admin setup has already been completed."},409,headers); }
      catch(e) { return reply({error:"Could not create the initial account. The email may already exist."},409,headers); }
      return reply({ok:true,message:"Super Admin account created."},201,headers);
    }
    if(path==="/api/auth/login"&&request.method==="POST") {
      const body=await readBody();
      if(!body || typeof body.email!=="string" || typeof body.password!=="string" || body.password.length>128) return reply({error:"Enter your email and password."},400,headers);
      const account=await auth.findByEmail(body.email.trim().toLowerCase());
      if(!account || account.status!=="active") return reply({error:"Email or password is incorrect."},401,headers);
      const computed=await passwordHash(body.password,account.password_salt);
      if(computed!==account.password_hash) return reply({error:"Email or password is incorrect."},401,headers);
      const token=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,"0")).join("");
      const now=new Date().toISOString(),expiresAt=Date.now()+7*24*60*60*1000;
      await auth.createSession({tokenHash:await hashText(token),userId:account.id,expiresAt,createdAt:now});
      await event(account.id,"auth.login","Successful sign-in");
      return reply({ok:true,token,expiresAt,user:{id:account.id,email:account.email,name:account.name,role:account.role}},200,headers);
    }
    if(path==="/api/auth/me"&&request.method==="GET") {
      const user=await getUser();
      if(!user) return reply({error:"Authentication required."},401,headers);
      return reply({ok:true,user},200,headers);
    }
    if(path==="/api/auth/logout"&&request.method==="POST") {
      const authHeader=request.headers.get("Authorization")||"",token=authHeader.startsWith("Bearer ")?authHeader.slice(7):"";
      if(token) { const user=await getUser(); await auth.revokeSession(await hashText(token)); if(user) await event(user.id,"auth.logout","Signed out"); }
      return reply({ok:true},200,headers);
    }
    if(path==="/api/admin/users"&&request.method==="GET") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers); if(user.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      return reply({users:await auth.listUsers()},200,headers);
    }
    if(path.startsWith("/api/admin/users/")&&path.endsWith("/password")&&request.method==="PATCH") {
      const actor=await getUser();
      if(!actor) return reply({error:"Authentication required."},401,headers);
      if(actor.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      const id=decodeURIComponent(path.slice("/api/admin/users/".length,-"/password".length));
      if(!/^[a-f0-9-]{36}$/i.test(id)) return reply({error:"Invalid member ID."},400,headers);
      const body=await readBody();
      if(!body||typeof body.password!=="string"||body.password.length<12||body.password.length>128) return reply({error:"New password must be 12–128 characters."},400,headers);
      const salt=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");
      const hash=await passwordHash(body.password,salt);
      if(!await auth.resetMemberPassword(id,hash,salt)) return reply({error:"Member not found."},404,headers);
      await event(actor.id,"member.password_reset","Password reset for member · "+id);
      return reply({ok:true,message:"Password updated. All member sessions have been signed out."},200,headers);
    }
    if(path.startsWith("/api/admin/users/")&&path.endsWith("/status")&&request.method==="PATCH") {
      const actor=await getUser();
      if(!actor) return reply({error:"Authentication required."},401,headers);
      if(actor.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      const id=decodeURIComponent(path.slice("/api/admin/users/".length,-"/status".length));
      if(!/^[a-f0-9-]{36}$/i.test(id)) return reply({error:"Invalid member ID."},400,headers);
      const body=await readBody();
      if(!body||!["active","suspended"].includes(body.status)) return reply({error:"Status must be active or suspended."},400,headers);
      if(!await auth.setUserStatus(id,body.status)) return reply({error:"Member not found."},404,headers);
      await event(actor.id,"member.status_changed",body.status+" · "+id);
      return reply({ok:true,status:body.status},200,headers);
    }
    if(path.startsWith("/api/admin/users/")&&path.endsWith("/detail")&&request.method==="GET") {
      const actor=await getUser();
      if(!actor) return reply({error:"Authentication required."},401,headers);
      if(actor.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      const id=decodeURIComponent(path.slice("/api/admin/users/".length,-"/detail".length));
      if(!/^[a-f0-9-]{36}$/i.test(id)) return reply({error:"Invalid member ID."},400,headers);
      const account=(await auth.listUsers()).find(x=>x.id===id);
      if(!account || account.role!=="member") return reply({error:"Member not found."},404,headers);
      const projectKeys=await env.AUDITS.list({prefix:"project:"+id+":",limit:100});
      const memberProjects=[];
      for(const item of projectKeys.keys||[]) {
        try { const raw=await env.AUDITS.get(item.name); if(raw) memberProjects.push(JSON.parse(raw)); } catch(e) {}
      }
      memberProjects.sort((a,b)=>new Date(b.updatedAt||b.createdAt)-new Date(a.updatedAt||a.createdAt));
      const memberAudits=[];
      let cursor;
      for(let page=0;page<10;page++) {
        const listed=await env.AUDITS.list({prefix:"audit:",limit:1000,...(cursor?{cursor}:{})});
        const keys=listed.keys||[];
        for(let i=0;i<keys.length;i+=40) {
          const batch=await Promise.all(keys.slice(i,i+40).map(async item=>{
            try { const raw=await env.AUDITS.get(item.name); return raw?JSON.parse(raw):null; } catch(e) { return null; }
          }));
          for(const audit of batch) if(audit&&audit.ownerId===id) memberAudits.push(audit);
        }
        if(listed.list_complete||!listed.cursor) break;
        cursor=listed.cursor;
      }
      memberAudits.sort((a,b)=>new Date(b.checkedAt)-new Date(a.checkedAt));
      const events=(await auth.listActivity(200)).filter(x=>x.user_id===id || (x.action==="member.created"&&String(x.detail||"").includes(account.email)));
      return reply({member:account,projects:memberProjects,audits:memberAudits.slice(0,100),activity:events.slice(0,50),summary:{websites:memberProjects.length,audits:memberAudits.length,averageScore:memberAudits.length?Math.round(memberAudits.reduce((sum,a)=>sum+(Number(a.score)||0),0)/memberAudits.length):null}},200,headers);
    }
    if(path==="/api/admin/users"&&request.method==="POST") {
      const actor=await getUser(); if(!actor) return reply({error:"Authentication required."},401,headers); if(actor.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      const body=await readBody();
      if(!body || typeof body.email!=="string" || typeof body.password!=="string" || body.password.length<12 || body.password.length>128 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email) || body.email.length>254) return reply({error:"Enter a valid email and a password of at least 12 characters."},400,headers);
      const salt=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join(""),now=new Date().toISOString();
      const member={id:crypto.randomUUID(),email:body.email.trim().toLowerCase(),name:String(body.name||"Member").trim().slice(0,80)||"Member",passwordSalt:salt,passwordHash:await passwordHash(body.password,salt),createdAt:now};
      try { await auth.createMember(member); await event(actor.id,"member.created","Created member "+member.email); }
      catch(e) { return reply({error:"Could not create member. The email may already be registered."},409,headers); }
      return reply({ok:true,user:{id:member.id,email:member.email,name:member.name,role:"member",status:"active",created_at:now}},201,headers);
    }
    if(path==="/api/admin/analytics"&&request.method==="GET") {
      const actor=await getUser();
      if(!actor) return reply({error:"Authentication required."},401,headers);
      if(actor.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      const users=(await auth.listUsers()).filter(x=>x.role==="member");
      const now=new Date(),days=30,dayMs=86400000,today=Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()),start=today-(days-1)*dayMs;
      const daily=Array.from({length:days},(_,i)=>{const d=new Date(start+(i*dayMs));return {date:d.toISOString().slice(0,10),signups:0,audits:0};});
      const dayMap=new Map(daily.map(x=>[x.date,x]));
      const memberMap=new Map(users.map(x=>[x.id,{id:x.id,name:x.name,email:x.email,status:x.status,websites:0,audits:0,scoreTotal:0,scoreCount:0}]));
      for(const user of users) {
        const projects=await env.AUDITS.list({prefix:"project:"+user.id+":",limit:100});
        memberMap.get(user.id).websites=(projects.keys||[]).length;
        const created=Date.parse(user.created_at||"");
        if(Number.isFinite(created)&&created>=start){const bucket=dayMap.get(new Date(created).toISOString().slice(0,10));if(bucket)bucket.signups++;}
      }
      let cursor,scanned=0,totalAudits=0;
      for(let page=0;page<10;page++) {
        const listed=await env.AUDITS.list({prefix:"audit:",limit:1000,...(cursor?{cursor}:{})});
        const keys=listed.keys||[];
        for(let i=0;i<keys.length;i+=40) {
          const batch=await Promise.all(keys.slice(i,i+40).map(async item=>{try{const raw=await env.AUDITS.get(item.name);return raw?JSON.parse(raw):null}catch(e){return null}}));
          for(const audit of batch) {
            if(!audit)continue;scanned++;
            const when=Date.parse(audit.checkedAt||"");
            if(!Number.isFinite(when)||when<start)continue;
            totalAudits++;
            const bucket=dayMap.get(new Date(when).toISOString().slice(0,10));if(bucket)bucket.audits++;
            const member=memberMap.get(audit.ownerId);
            if(member){member.audits++;member.scoreTotal+=Number(audit.score)||0;member.scoreCount++;}
          }
        }
        if(listed.list_complete||!listed.cursor)break;
        cursor=listed.cursor;
      }
      const members=[...memberMap.values()].sort((a,b)=>b.audits-a.audits||b.websites-a.websites).slice(0,10).map(x=>({...x,averageScore:x.scoreCount?Math.round(x.scoreTotal/x.scoreCount):null}));
      return reply({periodDays:days,totalMembers:users.length,activeMembers:users.filter(x=>x.status==="active").length,newMembers:daily.reduce((s,x)=>s+x.signups,0),websites:[...memberMap.values()].reduce((s,x)=>s+x.websites,0),audits:totalAudits,daily,topMembers:members,scannedAuditRecords:scanned},200,headers);
    }
    if(path==="/api/admin/intelligence"&&request.method==="GET") {
      const actor=await getUser();
      if(!actor) return reply({error:"Authentication required."},401,headers);
      if(actor.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      const days=30,dayMs=86400000,now=new Date(),today=Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()),start=today-(days-1)*dayMs;
      const daily=Array.from({length:days},(_,i)=>({date:new Date(start+i*dayMs).toISOString().slice(0,10),audits:0,scoreTotal:0,scoreCount:0}));
      const dayMap=new Map(daily.map(x=>[x.date,x]));
      const issueMap=new Map(),sites=new Set();
      let cursor,scanned=0,totalAudits=0,critical=0,warnings=0,scoreTotal=0,scoreCount=0;
      for(let page=0;page<10;page++) {
        const listed=await env.AUDITS.list({prefix:"audit:",limit:1000,...(cursor?{cursor}:{})});
        const keys=listed.keys||[];
        for(let i=0;i<keys.length;i+=40) {
          const batch=await Promise.all(keys.slice(i,i+40).map(async item=>{try{const raw=await env.AUDITS.get(item.name);return raw?JSON.parse(raw):null}catch(e){return null}}));
          for(const audit of batch) {
            if(!audit)continue;scanned++;
            const when=Date.parse(audit.checkedAt||"");
            if(!Number.isFinite(when)||when<start)continue;
            totalAudits++;if(audit.hostname)sites.add(audit.hostname);
            const bucket=dayMap.get(new Date(when).toISOString().slice(0,10));
            if(bucket){bucket.audits++;const score=Number(audit.score);if(Number.isFinite(score)){bucket.scoreTotal+=score;bucket.scoreCount++;}}
            const score=Number(audit.score);if(Number.isFinite(score)){scoreTotal+=score;scoreCount++;}
            for(const finding of Array.isArray(audit.findings)?audit.findings:[]) {
              const severity=["critical","warning","passed"].includes(finding?.severity)?finding.severity:"warning";
              if(severity==="critical")critical++;else if(severity==="warning")warnings++;
              if(severity==="passed")continue;
              const title=String(finding?.title||"Unspecified finding").slice(0,120);
              const category=String(finding?.category||"General").slice(0,60);
              const key=category+"::"+title;
              let item=issueMap.get(key);
              if(!item){item={title,category,severity,occurrences:0,sites:new Set(),recommendation:String(finding?.recommendation||"Review this finding and apply the recommended fix.").slice(0,500)};issueMap.set(key,item);}
              item.occurrences++;if(audit.hostname)item.sites.add(audit.hostname);
              if(severity==="critical")item.severity="critical";
            }
          }
        }
        if(listed.list_complete||!listed.cursor)break;
        cursor=listed.cursor;
      }
      const topIssues=[...issueMap.values()].map(x=>({...x,affectedSites:x.sites.size,sites:undefined})).sort((a,b)=>(b.severity==="critical"?3:1)*b.occurrences-(a.severity==="critical"?3:1)*a.occurrences||b.occurrences-a.occurrences).slice(0,12);
      const scoreTrend=daily.map(x=>({date:x.date,audits:x.audits,averageScore:x.scoreCount?Math.round(x.scoreTotal/x.scoreCount):null}));
      return reply({periodDays:days,audits:totalAudits,sites:sites.size,critical,warnings,averageScore:scoreCount?Math.round(scoreTotal/scoreCount):null,daily:scoreTrend,topIssues,scannedAuditRecords:scanned},200,headers);
    }
    if(path==="/api/admin/activity"&&request.method==="GET") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers); if(user.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      return reply({events:await auth.listActivity(150)},200,headers);
    }
    if(path==="/api/health"&&request.method==="GET") return reply({ok:true,service:"SEO Machine API",version:"0.1.0",database:!!env.DB,persistence:!!env.AUDITS},200,headers);

    if(path.startsWith("/api/projects/")&&path.endsWith("/monitor-history")&&request.method==="GET") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers);
      const id=decodeURIComponent(path.slice("/api/projects/".length,-"/monitor-history".length));
      if(!/^[a-f0-9-]{36}$/i.test(id)) return reply({error:"Invalid project ID."},400,headers);
      const key="project:"+user.id+":"+id,raw=await env.AUDITS.get(key); if(!raw) return reply({error:"Project not found."},404,headers);
      const listed=await env.AUDITS.list({prefix:"monitor:"+id+":",limit:100});
      const history=[];
      for(const item of listed.keys||[]) { try { const value=await env.AUDITS.get(item.name); if(value) history.push(JSON.parse(value)); } catch(e) {} }
      history.sort((a,b)=>new Date(b.checkedAt)-new Date(a.checkedAt));
      return reply({history:history.slice(0,50)},200,headers);
    }
    if(path==="/api/projects"&&request.method==="GET") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers);
      const listed=await env.AUDITS.list({prefix:"project:"+user.id+":",limit:100});
      const projects=[];
      for(const item of listed.keys||[]) { try { const raw=await env.AUDITS.get(item.name); if(raw) projects.push(JSON.parse(raw)); } catch(e) {} }
      projects.sort((a,b)=>new Date(b.updatedAt)-new Date(a.updatedAt));
      return reply({projects},200,headers);
    }
    if(path==="/api/projects"&&request.method==="POST") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers);
      const body=await readBody(),name=String(body?.name||"").trim().slice(0,80),rawUrl=String(body?.url||"").trim();
      if(!name||!rawUrl||rawUrl.length>2048) return reply({error:"Project name and website URL are required."},400,headers);
      let parsed; try { parsed=parseUrl(/^https?:\/\//i.test(rawUrl)?rawUrl:"https://"+rawUrl); } catch(e) { return reply({error:e.message||"Enter a valid public website URL."},400,headers); }
      const listed=await env.AUDITS.list({prefix:"project:"+user.id+":",limit:100});
      if((listed.keys||[]).length>=100) return reply({error:"You have reached the 100-project limit."},429,headers);
      const hostname=parsed.hostname.toLowerCase();
      for(const item of listed.keys||[]) { const raw=await env.AUDITS.get(item.name); if(raw) { const p=JSON.parse(raw); if(p.hostname===hostname) return reply({error:"This website is already in your projects."},409,headers); } }
      const now=new Date().toISOString(),project={id:crypto.randomUUID(),ownerId:user.id,name,url:parsed.origin+parsed.pathname.replace(/\/$/,""),hostname,description:String(body.description||"").trim().slice(0,300),status:"active",monitoringEnabled:false,monitorIntervalHours:24,nextCheckAt:null,lastCheckAt:null,lastMonitorStatus:"not_configured",createdAt:now,updatedAt:now};
      await env.AUDITS.put("project:"+user.id+":"+project.id,JSON.stringify(project));
      await event(user.id,"project.created","Created project "+project.name+" · "+project.hostname);
      return reply({project},201,headers);
    }
    if(path.startsWith("/api/projects/")&&(request.method==="PATCH"||request.method==="DELETE")) {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers);
      const id=decodeURIComponent(path.slice("/api/projects/".length));
      if(!/^[a-f0-9-]{36}$/i.test(id)) return reply({error:"Invalid project ID."},400,headers);
      const key="project:"+user.id+":"+id,raw=await env.AUDITS.get(key); if(!raw) return reply({error:"Project not found."},404,headers);
      const project=JSON.parse(raw);
      if(request.method==="DELETE") { await env.AUDITS.delete(key); await event(user.id,"project.deleted","Deleted project "+project.name); return reply({ok:true},200,headers); }
      const body=await readBody();
      if(typeof body?.name==="string") { const name=body.name.trim().slice(0,80); if(!name) return reply({error:"Project name cannot be empty."},400,headers); project.name=name; }
      if(typeof body?.description==="string") project.description=body.description.trim().slice(0,300);
      if(typeof body?.status==="string"&&["active","paused"].includes(body.status)) project.status=body.status;
      if(typeof body?.monitoringEnabled==="boolean") {
        project.monitoringEnabled=body.monitoringEnabled;
        project.nextCheckAt=body.monitoringEnabled?new Date().toISOString():null;
      }
      if([6,12,24].includes(Number(body?.monitorIntervalHours))) {
        project.monitorIntervalHours=Number(body.monitorIntervalHours);
        if(project.monitoringEnabled) project.nextCheckAt=new Date().toISOString();
      }
      project.updatedAt=new Date().toISOString(); await env.AUDITS.put(key,JSON.stringify(project));
      await event(user.id,"project.updated","Updated project "+project.name);
      return reply({project},200,headers);
    }
    if(path==="/api/score-history"&&request.method==="GET") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers);
      const grouped=new Map();let cursor,scanned=0;
      for(let page=0;page<10;page++) {
        const listed=await env.AUDITS.list({prefix:"audit:",limit:1000,...(cursor?{cursor}:{})});
        const keys=listed.keys||[];
        for(let i=0;i<keys.length;i+=40) {
          const batch=await Promise.all(keys.slice(i,i+40).map(async item=>{try{const raw=await env.AUDITS.get(item.name);return raw?JSON.parse(raw):null}catch(e){return null}}));
          for(const audit of batch) {
            if(!audit||audit.ownerId!==user.id||!audit.hostname||!Number.isFinite(Number(audit.score)))continue;
            scanned++;const hostname=String(audit.hostname).toLowerCase().replace(/^www\./,"");
            if(!grouped.has(hostname))grouped.set(hostname,{hostname,url:audit.url,title:audit.title||"",history:[]});
            const site=grouped.get(hostname);
            if(new Date(audit.checkedAt)>new Date(site.history[site.history.length-1]?.checkedAt||0)){site.url=audit.url||site.url;site.title=audit.title||site.title;}
            site.history.push({id:audit.id||null,url:audit.url,checkedAt:audit.checkedAt,score:Number(audit.score),summary:audit.summary||{passed:0,warnings:0,critical:0}});
          }
        }
        if(listed.list_complete||!listed.cursor)break;cursor=listed.cursor;
      }
      const sites=[...grouped.values()].map(site=>{site.history.sort((a,b)=>new Date(a.checkedAt)-new Date(b.checkedAt));const first=site.history[0],latest=site.history[site.history.length-1],previous=site.history.length>1?site.history[site.history.length-2]:null;return {...site,audits:site.history.length,currentScore:latest.score,previousScore:previous?previous.score:null,change:previous?latest.score-previous.score:null,trend:!previous?"new":latest.score>previous.score?"improving":latest.score<previous.score?"declining":"stable",firstScore:first.score,lastAuditAt:latest.checkedAt,history:site.history.slice(-30).reverse()}}).sort((a,b)=>new Date(b.lastAuditAt)-new Date(a.lastAuditAt));
      return reply({sites,totalSites:sites.length,totalAudits:sites.reduce((sum,x)=>sum+x.audits,0),scannedRecords:scanned,retentionDays:30},200,headers);
    }
    if(path==="/api/audits"&&request.method==="GET") {
      const user=await getUser();
      if(!user) return reply({error:"Authentication required."},401,headers);
      const records=[]; let cursor;
      for(let page=0;page<5;page++) {
        const listed=await env.AUDITS.list({prefix:"audit:",limit:1000,...(cursor?{cursor}:{})});
        const keys=listed.keys||[];
        for(let i=0;i<keys.length;i+=40) {
          const batch=await Promise.all(keys.slice(i,i+40).map(async item=>{
            try { const raw=await env.AUDITS.get(item.name); return raw?JSON.parse(raw):null; } catch(e) { return null; }
          }));
          for(const audit of batch) if(audit&&audit.ownerId===user.id) records.push(audit);
        }
        if(listed.list_complete||!listed.cursor) break;
        cursor=listed.cursor;
      }
      records.sort((a,b)=>new Date(b.checkedAt)-new Date(a.checkedAt));
      return reply({audits:records.slice(0,100),count:records.length},200,headers);
    }
    if(path==="/api/audit"&&request.method==="POST") {
      const user=await getUser();
      if(!user) return reply({error:"Authentication required."},401,headers);
      const result=await doAudit(request,env,user);
      if(result.status===200) {
        const payload=await result.clone().json();
        await event(user.id,"audit.completed","Audited "+payload.audit.hostname+" · score "+payload.audit.score);
      }
      const h=new Headers(result.headers); Object.keys(headers).forEach(k=>{if(headers[k])h.set(k,headers[k]);});
      return new Response(result.body,{status:result.status,headers:h});
    }
    return reply({error:"Not found"},404,headers);
    } catch (error) {
      console.error("[SEO Machine API]", new URL(request.url).pathname, error);
      return reply({error:"Internal server error",diagnostic:String(error?.message || error)},500,headers);
    }
  },
  async scheduled(event,env,ctx) {
    ctx.waitUntil((async()=>{
      let cursor;
      for(let page=0;page<10;page++) {
        const listed=await env.AUDITS.list({prefix:"project:",limit:500,...(cursor?{cursor}:{})});
        for(const item of listed.keys||[]) {
          if(item.name.split(":").length!==3) continue;
          let project; try { const raw=await env.AUDITS.get(item.name); if(!raw) continue; project=JSON.parse(raw); } catch(e) { continue; }
          if(!project.monitoringEnabled||project.status!=="active"||!project.nextCheckAt||new Date(project.nextCheckAt).getTime()>Date.now()) continue;
          let result={ok:false,httpStatus:null,error:"Connection failed or timed out"};
          try {
            const target=parseUrl(project.url);
            const response=await fetch(target.href,{method:"GET",redirect:"manual",signal:AbortSignal.timeout(10000),headers:{"user-agent":"SEOMachineMonitor/1.0","accept":"text/html,application/xhtml+xml"}});
            if(response.body) await response.body.cancel();
            result={ok:response.status>=200&&response.status<400,httpStatus:response.status,error:null};
          } catch(e) {}
          const checkedAt=new Date().toISOString(),record={projectId:project.id,hostname:project.hostname,checkedAt,ok:result.ok,httpStatus:result.httpStatus,error:result.error};
          await env.AUDITS.put("monitor:"+project.id+":"+Date.now()+":"+crypto.randomUUID(),JSON.stringify(record),{expirationTtl:2592000});
          project.lastCheckAt=checkedAt; project.lastHttpStatus=result.httpStatus; project.lastMonitorStatus=result.ok?"online":"down";
          project.nextCheckAt=new Date(Date.now()+(Number([6,12,24].includes(project.monitorIntervalHours)?project.monitorIntervalHours:24))*3600000).toISOString();
          project.updatedAt=checkedAt; await env.AUDITS.put(item.name,JSON.stringify(project));
        }
        if(listed.list_complete||!listed.cursor) break;
        cursor=listed.cursor;
      }
    })());
  }

};
