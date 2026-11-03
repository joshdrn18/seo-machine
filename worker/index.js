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
function analyze(html,url,status,headers) {
  const title=extract(html,/<title[^>]*>([\s\S]*?)<\/title>/i);
  const description=extract(html,/<meta\b(?=[^>]*name=["']description["'])(?=[^>]*content=["']([^"']*)["'])[^>]*>/i) || extract(html,/<meta\b(?=[^>]*content=["']([^"']*)["'])(?=[^>]*name=["']description["'])[^>]*>/i);
  const canonical=/<link\b(?=[^>]*rel=["']canonical["'])(?=[^>]*href=["'][^"']+["'])[^>]*>/i.test(html);
  const h1=(html.match(/<h1\b/gi)||[]).length, headings=(html.match(/<h[1-6]\b/gi)||[]).length;
  const imgs=html.match(/<img\b[^>]*>/gi)||[], missing=imgs.filter(x=>!/\balt\s*=/.test(x)).length;
  const viewport=/<meta\b(?=[^>]*name=["']viewport["'])/i.test(html);
  const robots=extract(html,/<meta\b(?=[^>]*name=["']robots["'])(?=[^>]*content=["']([^"']*)["'])[^>]*>/i);
  const findings=[];
  function add(category,severity,titleText,details,recommendation){findings.push({category:category,severity:severity,title:titleText,details:details,recommendation:recommendation});}
  add("Technical",status>=200&&status<400?"passed":"critical","HTTP response","The page returned HTTP "+status+".","Keep the page reachable and return a successful status code.");
  add("On-page",!title?"critical":title.length>=30&&title.length<=60?"passed":"warning","Title tag",title?"Found a "+title.length+"-character title: "+title.slice(0,100):"No title tag was detected.","Add a unique, descriptive title; aim for roughly 30–60 characters.");
  add("On-page",!description?"critical":description.length>=70&&description.length<=160?"passed":"warning","Meta description",description?"Found a "+description.length+"-character description.":"No meta description was detected.","Write a compelling page-specific description of roughly 70–160 characters.");
  add("On-page",h1===1?"passed":"warning","H1 heading","Found "+h1+" H1 heading(s).","Use one clear primary H1 that describes the page.");
  add("On-page",headings>0?"passed":"warning","Heading structure","Detected "+headings+" heading elements.","Organize content with descriptive, logically nested headings.");
  add("Technical",canonical?"passed":"warning","Canonical URL",canonical?"A canonical link element was found.":"No canonical link element was detected.","Add an absolute canonical URL when duplicate or alternate URLs may exist.");
  add("Technical",viewport?"passed":"warning","Mobile viewport",viewport?"A viewport meta tag was found.":"No viewport meta tag was detected.","Add a responsive viewport meta tag for mobile browsers.");
  add("Images",missing===0?"passed":"warning","Image alternative text",missing+" of "+imgs.length+" images appear to be missing an alt attribute.","Add useful alt text to informative images and empty alt text to decorative images.");
  add("Technical",/noindex/i.test(robots)?"critical":"passed","Robots directives",robots?"Robots meta: "+robots:"No noindex directive was detected in the robots meta tag.","Confirm indexing directives match your publishing intent.");
  add("Security",url.protocol==="https:"?"passed":"critical","HTTPS",url.protocol==="https:"?"The URL uses HTTPS.":"The URL uses HTTP.","Serve the site over HTTPS and redirect HTTP to HTTPS.");
  add("Technical",(headers.get("content-type")||"").includes("text/html")?"passed":"warning","HTML content type","Content-Type: "+(headers.get("content-type")||"not provided")+".","Serve HTML documents with a text/html content type.");
  const passed=findings.filter(f=>f.severity==="passed").length, warnings=findings.filter(f=>f.severity==="warning").length, critical=findings.filter(f=>f.severity==="critical").length;
  const score=Math.max(0,Math.round(findings.reduce((n,f)=>n+(f.severity==="passed"?10:f.severity==="warning"?5:0),0)/findings.length*10));
  return {url:url.href,hostname:url.hostname,status:status,title:title,description:description,score:score,findings:findings,summary:{passed:passed,warnings:warnings,critical:critical,total:findings.length},checkedAt:new Date().toISOString()};
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
  const audit=analyze(html,target,response.status,response.headers);
  audit.ownerId=user.id; audit.ownerEmail=user.email;
  try { await env.AUDITS.put("audit:"+audit.checkedAt+":"+crypto.randomUUID(),JSON.stringify(audit),{expirationTtl:2592000}); } catch(e) { return reply({error:"Audit completed but could not be saved. Please retry."},503); }
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
  listUsers() {
    return this.ctx.storage.sql.exec("SELECT id,email,name,role,status,created_at FROM accounts ORDER BY created_at DESC").toArray();
  }
  listActivity(limit=100) {
    return this.ctx.storage.sql.exec("SELECT x.id,x.user_id,x.action,x.detail,x.created_at,a.email,a.name,a.role FROM activity x LEFT JOIN accounts a ON a.id=x.user_id ORDER BY x.id DESC LIMIT ?",Math.min(Math.max(Number(limit)||100,1),200)).toArray();
  }
}

export default {
  async fetch(request,env) {
    const origin=request.headers.get("Origin")||"";
    const previewOrigin=/^https:\/\/[a-z0-9-]+\.seo-machine-5ay\.pages\.dev$/i.test(origin);
    const allowed=(env.APP_ORIGIN&&origin===env.APP_ORIGIN)||previewOrigin?origin:"";
    const headers={"access-control-allow-methods":"GET, POST, OPTIONS","access-control-allow-headers":"content-type,authorization,x-bootstrap-token","vary":"Origin"};
    if(allowed) headers["access-control-allow-origin"]=allowed;
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
      const bits = await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:new TextEncoder().encode(salt),iterations:120000},key,256);
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
      if(!env.BOOTSTRAP_TOKEN || request.headers.get("x-bootstrap-token")!==env.BOOTSTRAP_TOKEN) return reply({error:"Invalid setup token."},403,headers);
      const body=await readBody();
      if(!body || typeof body.email!=="string" || typeof body.password!=="string" || body.password.length<12 || body.password.length>128 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email) || body.email.length>254) return reply({error:"Enter a valid email and a password of at least 12 characters."},400,headers);
      const salt=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");
      const now=new Date().toISOString();
      const user={id:crypto.randomUUID(),email:body.email.trim().toLowerCase(),name:String(body.name||"Super Admin").trim().slice(0,80)||"Super Admin",passwordSalt:salt,passwordHash:await passwordHash(body.password,salt),createdAt:now};
      try { const result=await auth.createFirstAdmin(user); if(!result.created) return reply({error:"Initial admin setup has already been completed."},409,headers); }
      catch(e) { return reply({error:"Could not create the initial account. The email may already exist."},409,headers); }
      return reply({ok:true,message:"Super Admin created. Remove the bootstrap token from Worker secrets now."},201,headers);
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
    if(path==="/api/admin/activity"&&request.method==="GET") {
      const user=await getUser(); if(!user) return reply({error:"Authentication required."},401,headers); if(user.role!=="super_admin") return reply({error:"Forbidden."},403,headers);
      return reply({events:await auth.listActivity(150)},200,headers);
    }
    if(path==="/api/health"&&request.method==="GET") return reply({ok:true,service:"SEO Machine API",version:"0.1.0",database:!!env.DB,persistence:!!env.AUDITS},200,headers);
    if(path==="/api/audit"&&request.method==="POST") {
      const user=await getUser();
      if(!user) return reply({error:"Authentication required."},401,headers);
      const result=await doAudit(request,env,user);
      if(result.status===200) {
        const payload=JSON.parse(result.body);
        await event(user.id,"audit.completed","Audited "+payload.audit.hostname+" · score "+payload.audit.score);
      }
      const h=new Headers(result.headers); Object.keys(headers).forEach(k=>{if(headers[k])h.set(k,headers[k]);});
      return new Response(result.body,{status:result.status,headers:h});
    }
    return reply({error:"Not found"},404,headers);
  }
};
