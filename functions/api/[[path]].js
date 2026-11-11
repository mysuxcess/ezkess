// EZKESS server: Cloudflare Pages Function. Bindings: KV "EZ"; secrets ADMIN_PASSWORD, SESSION_SECRET.
const enc=new TextEncoder(),J=(o,s=200,h)=>new Response(JSON.stringify(o),{status:s,headers:Object.assign({"content-type":"application/json","cache-control":"no-store"},h||{})});
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function sig(env,m){const k=await crypto.subtle.importKey("raw",enc.encode(env.SESSION_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return hex(await crypto.subtle.sign("HMAC",k,enc.encode(m)))}
const same=(a,b)=>{if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0};
async function isAdmin(req,env){const m=(req.headers.get("cookie")||"").match(/(?:^|; )ez=(\d+)\.([a-f0-9]+)/);return !!m&&Number(m[1])>Date.now()&&same(m[2],await sig(env,"admin."+m[1]))}
const CK=["resp","rec","hold"],AK=["offer","tx","done","rv","ended"],FID=/^r[a-f0-9]{32}$/;
function merge(o,inc,role,fid){
  if(!o){if(role!=="customer"||!inc.req||inc.req.fid!==fid)return null;o={_t:Date.now(),req:inc.req}}
  const n=Object.assign({},o);
  for(const k of role==="admin"?AK:CK)if(k in inc){if(inc[k]==null)delete n[k];else n[k]=inc[k]}
  if(role==="customer"){
    if(n.resp&&!(o.offer&&o.offer.ok))n.resp=o.resp;
    if(n.rec&&!o.tx)n.rec=o.rec;
    if(inc.ended&&inc.resp&&inc.resp.ok===0)n.ended=1;
  }
  const own=role==="admin"?"ad":"cu";
  n.msgs=(o.msgs||[]).filter(m=>m.f!==own).concat((inc.msgs||[]).filter(m=>m.f===own)).sort((a,b)=>(a.id||0)-(b.id||0));
  return n;
}
// customers never receive admin-only data or the private WhatsApp targets
function forCustomer(a){const c=JSON.parse(JSON.stringify(a));delete c.rv;delete c._t;if(c.req)delete c.req.hp;
  (c.msgs||[]).forEach(m=>delete m.to);
  if(c.done)c.done.rows=c.done.rows.filter(r=>r[0]!=="Outcome"&&r[0]!=="Admin notes");return c}
export async function onRequest({request:req,env,params}){
  const p=[].concat(params.path||[]).join("/"),m=req.method,adm=await isAdmin(req,env),key=req.headers.get("x-key")||"";
  const body=async()=>{try{return await req.json()}catch(e){return {}}};
  if(p==="login"&&m==="POST"){
    const ip=req.headers.get("cf-connecting-ip")||"x",rk="rl:"+ip,n=Number(await env.EZ.get(rk))||0;
    if(n>=8)return J({error:"locked"},429);
    const b=await body(),ok=typeof b.password==="string"&&same(await sig(env,"pw."+b.password),await sig(env,"pw."+env.ADMIN_PASSWORD));
    if(!ok){await env.EZ.put(rk,String(n+1),{expirationTtl:600});await new Promise(r=>setTimeout(r,500));return J({error:"bad"},401)}
    const exp=Date.now()+8*3600e3;
    return J({ok:1},200,{"set-cookie":`ez=${exp}.${await sig(env,"admin."+exp)}; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict`});
  }
  if(p==="logout"&&m==="POST")return J({ok:1},200,{"set-cookie":"ez=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"});
  if(p==="public")return J({lw:(await env.EZ.get("settings",{type:"json"})||{}).lw||""});
  if(p.startsWith("admin/")){
    if(!adm)return J({error:"auth"},401);
    if(p==="admin/state"&&m==="GET"){
      const l=await env.EZ.list({prefix:"app:"}),apps=(await Promise.all(l.keys.map(k=>env.EZ.get(k.name,{type:"json"})))).filter(Boolean).sort((a,b)=>a._t-b._t);
      return J({apps,vault:await env.EZ.get("vault",{type:"json"})||[],lw:(await env.EZ.get("settings",{type:"json"})||{}).lw||""});
    }
    if(p==="admin/vault"&&m==="PUT"){const b=await body();if(!Array.isArray(b))return J({error:"bad"},400);await env.EZ.put("vault",JSON.stringify(b));return J({ok:1})}
    if(p==="admin/settings"&&m==="PUT"){const b=await body();await env.EZ.put("settings",JSON.stringify({lw:String(b.lw||"").replace(/\D/g,"")}));return J({ok:1})}
  }
  if(p==="mine"&&m==="GET"){const a=FID.test(key)&&await env.EZ.get("app:"+key,{type:"json"});return a?J({app:forCustomer(a)}):J({error:"none"},404)}
  if(p.startsWith("app/")&&m==="PUT"){
    const fid=p.slice(4);if(!FID.test(fid))return J({error:"bad"},400);
    const role=adm?"admin":key===fid?"customer":null;if(!role)return J({error:"auth"},403);
    const n=merge(await env.EZ.get("app:"+fid,{type:"json"}),await body(),role,fid);if(!n)return J({error:"bad"},400);
    await env.EZ.put("app:"+fid,JSON.stringify(n));return J({ok:1});
  }
  if(p.startsWith("file/")){
    const k=p.slice(5),fid=k.split("-")[0];if(!FID.test(fid)||!/^r[a-f0-9]{32}-(1|2|vn)$/.test(k))return J({error:"bad"},400);
    if(!adm&&key!==fid)return J({error:"auth"},403);
    if(m==="GET"){const u=await env.EZ.get("file:"+k);return u?J({u}):J({error:"none"},404)}
    if(m==="PUT"){const b=await body();if(typeof b.u!=="string"||b.u.length>12e6||!/^data:(image|audio)\/|^data:application\/pdf/.test(b.u))return J({error:"bad"},400);await env.EZ.put("file:"+k,b.u);return J({ok:1})}
  }
  return J({error:"not found"},404);
}
