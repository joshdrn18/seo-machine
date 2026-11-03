const reply = (data, status, headers) => new Response(JSON.stringify(data), {status:status || 200,headers:Object.assign({"content-type":"application/json; charset=utf-8","cache-control":"no-store"},headers || {})});
function blocked(host) {
  const h=host.toLowerCase();
  if(h==="localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if(/^([0-9]{1,3}\\.){3}[0-9]{1,3}$/.test(h)) {
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
function extract(html, regex) { const m=regex.exec(html); return m ? m[1].replace(/<[^>]*>/g," ").replace(/&amp;/gi,"&").replace(/&nbsp;/gi," ").replace(/&quot;/gi,'"').replace(/&#39;/gi,"'").replace(/\\s+/g," ").trim() : ""; }
function analyze(html,url,status,headers) {
  const title=extract(html,/<title[^>]*>([\\s\\S]*?)<\\/title>/i);
  const description=extract(html,/<meta\\b(?=[^>]*name=["']description["'])(?=[^>]*content=["']([^"']*)["'])[^>]*>/i) || extract(html,/<meta\\b(?=[^>]*content=["']([^"']*)["'])(?=[^>]*name=["']description["'])[^>]*>/i);
  const canonical=/<link\\b(?=[^>]*rel=["']canonical["'])(?=[^>]*href=["'][^"']+["'])[^>]*>/i.test(html);
  const h1=(html.match(/<h1\\b/gi)||[]).length, headings=(html.match(/<h[1-6]\\b/gi)||[]).length;
  const imgs=html.match(/<img\\b[^>]*>/gi)||[], missing=imgs.filter(x=>!/\\balt\\s*=/.test(x)).length;
  const viewport=/<meta\\b(?=[^>]*name=["']viewport["'])/i.test(html);
  const robots=extract(html,/<meta\\b(?=[^>]*name=["']robots["'])(?=[^>]*content=["']([^"']*)["'])[^>]*>/i);
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
async function doAudit(request) {
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
  return reply({audit:analyze(html,target,response.status,response.headers)});
}
export default {
  async fetch(request,env) {
    const origin=request.headers.get("Origin")||"", allowed=env.APP_ORIGIN&&origin===env.APP_ORIGIN?origin:"";
    const headers={"access-control-allow-methods":"GET, POST, OPTIONS","access-control-allow-headers":"content-type","vary":"Origin"};
    if(allowed) headers["access-control-allow-origin"]=allowed;
    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:headers});
    const path=new URL(request.url).pathname;
    if(path==="/api/health"&&request.method==="GET") return reply({ok:true,service:"SEO Machine API",version:"0.1.0",database:!!env.DB},200,headers);
    if(path==="/api/audit"&&request.method==="POST") { const result=await doAudit(request); const h=new Headers(result.headers); Object.keys(headers).forEach(k=>{if(headers[k])h.set(k,headers[k]);}); return new Response(result.body,{status:result.status,headers:h}); }
    return reply({error:"Not found"},404,headers);
  }
};
