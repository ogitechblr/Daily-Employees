// OGI Daily Employee Entry - Cloudflare Worker + D1 backend (same API as server.js).
// Tables are created automatically on first request.
const enc=new TextEncoder(), IST=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Kolkata'});
const dayKey=d=>IST.format(d||new Date()), now=()=>new Date().toISOString();
const bad=(m,c=400)=>Object.assign(new Error(m),{code:c});
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
const safeEq=(a,b)=>{if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0};
const cfg=e=>({ADMIN:e.ADMIN_PASSWORD||'Ogi@2026@EmpLogIN',EMP:e.DEFAULT_EMPLOYEE_PASSWORD||'OGI@2026',SECRET:e.SESSION_SECRET||'change-this-secret-ogi-2026'});
async function pbk(pw,salt){const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:20000},k,256))}
async function hashPw(pw){const s=hex(crypto.getRandomValues(new Uint8Array(12)));return s+':'+await pbk(pw,s)}
async function checkPw(pw,h){if(!h)return false;const [s,x]=h.split(':');return safeEq(await pbk(String(pw),s),x)}
async function hmac(secret,msg){const k=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',k,enc.encode(msg)))}
const sign=async(o,sec)=>{const p=hex(enc.encode(JSON.stringify(o)));return p+'.'+await hmac(sec,p)};
async function session(req,sec){const m=/(?:^|; )sid=([^;]+)/.exec(req.headers.get('cookie')||'');if(!m)return null;try{const [p,s]=m[1].split('.');if(!safeEq(s,await hmac(sec,p)))return null;const o=JSON.parse(new TextDecoder().decode(unhex(p)));return o.exp>Date.now()?o:null}catch{return null}}
const pub=e=>({employeeNo:e.employee_no,name:e.name,active:e.active!==0,pinHash:!!e.pin_hash});
const validId=v=>{v=String(v||'').trim();if(!/^[\w\-./ ]{1,40}$/.test(v))throw bad('Invalid Work ID');return v};
const admin=s=>{if(s.role!=='admin')throw bad('Admin only',403)};
let ready=false;
async function init(DB){if(ready)return;await DB.batch([
 DB.prepare('CREATE TABLE IF NOT EXISTS employees(employee_no TEXT PRIMARY KEY,name TEXT NOT NULL,pin_hash TEXT,active INTEGER DEFAULT 1)'),
 DB.prepare('CREATE TABLE IF NOT EXISTS work_ids(id TEXT PRIMARY KEY)'),
 DB.prepare('CREATE TABLE IF NOT EXISTS records(date TEXT NOT NULL,employee_no TEXT NOT NULL,status TEXT,data TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(date,employee_no))')]);ready=true}
const allEmps=async DB=>(await DB.prepare('SELECT * FROM employees ORDER BY employee_no').all()).results;
const workIds=async DB=>(await DB.prepare('SELECT id FROM work_ids ORDER BY rowid').all()).results.map(x=>x.id);

function apply(r,type,id,t){
  const hrs=a=>(new Date(t)-new Date(a))/36e5;
  const ev=(ty,x)=>{r.events.push({at:t,type:ty,...x});r.lastActivityAt=t};
  const active=()=>r.workSessions.find(w=>!w.endAt),openBreak=()=>r.breaks.find(b=>!b.endAt);
  const endWork=ty=>{const a=active();if(a){a.endAt=t;ev(ty,{workId:a.workId,dur:hrs(a.startAt)})}};
  const endBreak=()=>{const b=openBreak();if(b){b.endAt=t;ev('BREAK_ENDED',{dur:hrs(b.startAt)})}};
  const begin=(w,ty)=>{r.workSessions.push({workId:w,startAt:t,endAt:null});r.currentWorkId=w;r.status='WORKING';ev(ty,{workId:w})};
  if(type==='login'){if(r.status&&r.status!=='LOGGED_OUT')throw bad('Already logged in');r.status='LOGGED_IN';r.logoutAt=null;r.currentWorkId=null;ev('LOGIN');return}
  if(!r.status||r.status==='LOGGED_OUT')throw bad('Please log in first');
  switch(type){
    case 'start':if(r.status!=='LOGGED_IN')throw bad('Close or resume current work first');begin(id,'WORK_STARTED');break;
    case 'switch':if(r.status!=='WORKING')throw bad('No active Work ID to switch from');if(id===r.currentWorkId)throw bad('That Work ID is already active');endWork('WORK_COMPLETED');begin(id,'WORK_STARTED');break;
    case 'break-start':if(r.status!=='WORKING')throw bad('Not currently working');endWork('WORK_PAUSED');r.breaks.push({startAt:t,endAt:null});r.status='ON_BREAK';ev('BREAK_STARTED');break;
    case 'break-end':if(r.status!=='ON_BREAK')throw bad('Not on break');endBreak();begin(r.currentWorkId,'WORK_RESUMED');break;
    case 'close-work':if(r.status==='LOGGED_IN')throw bad('No open work');endBreak();endWork('WORK_COMPLETED');r.currentWorkId=null;r.status='LOGGED_IN';ev('CLOSED_WORK');break;
    case 'logout':endBreak();endWork('WORK_COMPLETED');r.status='LOGGED_OUT';r.logoutAt=t;r.currentWorkId=null;ev('LOGOUT');break;
    default:throw bad('Unknown action');
  }
}
async function closeStale(DB,no){
  const today=dayKey();
  const rows=(await DB.prepare("SELECT date,data,version FROM records WHERE employee_no=? AND date<? AND status!='LOGGED_OUT'").bind(no,today).all()).results;
  for(const x of rows){const r=JSON.parse(x.data),t=new Date(x.date+'T23:59:59+05:30').toISOString();
    r.workSessions.forEach(w=>{if(!w.endAt)w.endAt=t});r.breaks.forEach(b=>{if(!b.endAt)b.endAt=t});
    r.status='LOGGED_OUT';r.logoutAt=t;r.currentWorkId=null;r.events.push({at:t,type:'AUTO_LOGOUT'});
    await DB.prepare("UPDATE records SET data=?,status='LOGGED_OUT',version=version+1 WHERE date=? AND employee_no=? AND version=?").bind(JSON.stringify(r),x.date,no,x.version).run()}
}
async function act(DB,emp,type,workId){
  const id=['start','switch'].includes(type)?validId(workId):null;
  for(let i=0;i<4;i++){
    await closeStale(DB,emp.employee_no);
    const date=dayKey(),t=now(),row=await DB.prepare('SELECT data,version FROM records WHERE date=? AND employee_no=?').bind(date,emp.employee_no).first();
    let r=row?JSON.parse(row.data):null;
    if(!r){if(type!=='login')throw bad('Please log in first');r={employeeNo:emp.employee_no,name:emp.name,attendance:'PRESENT',loginAt:t,workSessions:[],breaks:[],events:[]}}
    apply(r,type,id,t);
    const js=JSON.stringify(r);
    const res=row?await DB.prepare('UPDATE records SET data=?,status=?,version=version+1 WHERE date=? AND employee_no=? AND version=?').bind(js,r.status,date,emp.employee_no,row.version).run()
                 :await DB.prepare('INSERT OR IGNORE INTO records(date,employee_no,status,data) VALUES(?,?,?,?)').bind(date,emp.employee_no,r.status,js).run();
    if(res.meta.changes){if(id)await DB.prepare('INSERT OR IGNORE INTO work_ids(id) VALUES(?)').bind(id).run();return r}
  }
  throw bad('Busy, please try again',409);
}
const dayMap=rows=>{const o={};rows.forEach(x=>o[x.employee_no]=JSON.parse(x.data));return o};

const routes={
 'POST login':async({env,b,c,headers})=>{
   let user=null;
   if(b.role==='admin'){if(safeEq(await hmac(c.SECRET,String(b.password||'')),await hmac(c.SECRET,c.ADMIN)))user={role:'admin'}}
   else{const k=String(b.employeeNo||b.name||'').trim().toLowerCase(),L=(await allEmps(env.DB)).filter(e=>e.active!==0&&(e.employee_no.toLowerCase()===k||e.name.toLowerCase()===k));
     if(L.length>1&&!L.every(e=>e.employee_no.toLowerCase()===k))throw bad('Several employees have this name. Use your Employee Number.');
     const e=L[0];if(e&&await checkPw(b.pin,e.pin_hash))user={role:'employee',employeeNo:e.employee_no,name:e.name}}
   if(!user)throw bad('Invalid credentials',401);
   headers.append('Set-Cookie','sid='+await sign({...user,exp:Date.now()+12*36e5},c.SECRET)+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200');
   return {user}},
 'POST logout':async({headers})=>{headers.append('Set-Cookie','sid=; HttpOnly; Secure; Path=/; Max-Age=0');return {ok:true}},
 'GET me':async({s})=>({user:s}),
 'GET bootstrap':async({env,s})=>{const w=await workIds(env.DB);if(s.role==='admin')return {user:s,workIds:w};
   const row=await env.DB.prepare('SELECT data FROM records WHERE date=? AND employee_no=?').bind(dayKey(),s.employeeNo).first();return {user:s,workIds:w,record:row?JSON.parse(row.data):null}},
 'POST work-ids':async({env,b})=>{await env.DB.prepare('INSERT OR IGNORE INTO work_ids(id) VALUES(?)').bind(validId(b.workId)).run();return {workIds:await workIds(env.DB)}},
 'POST action':async({env,b,s})=>{if(s.role!=='employee')throw bad('Employees only',403);
   const e=(await allEmps(env.DB)).find(e=>e.employee_no===s.employeeNo);if(!e||e.active===0)throw bad('Account disabled',403);return {record:await act(env.DB,e,b.type,b.workId)}},
 'GET activity':async({env,s,u})=>{admin(s);const d=u.searchParams.get('date')||dayKey();
   const rows=(await env.DB.prepare('SELECT employee_no,data FROM records WHERE date=?').bind(d).all()).results;return {employees:(await allEmps(env.DB)).map(pub),day:{employees:dayMap(rows)}}},
 'GET report':async({env,s,u})=>{admin(s);const f=u.searchParams.get('from'),t=u.searchParams.get('to');
   const rows=(await env.DB.prepare('SELECT date,employee_no,data FROM records WHERE date>=? AND date<=? ORDER BY date').bind(f,t).all()).results,by={};
   rows.forEach(x=>(by[x.date]||(by[x.date]={}))[x.employee_no]=JSON.parse(x.data));
   return {employees:(await allEmps(env.DB)).map(pub),days:Object.keys(by).sort().map(d=>({date:d,employees:by[d]}))}},
 'GET employees':async({env,s})=>{admin(s);return {employees:(await allEmps(env.DB)).map(pub)}},
 'POST employees':async({env,b,s,c})=>{admin(s);const pin=String(b.pin||c.EMP);if(pin.length<4)throw bad('Password must be at least 4 characters');
   const names=(Array.isArray(b.names)?b.names:[b.name]).map(x=>String(x||'').trim()).filter(Boolean);if(!names.length)throw bad('Name required');
   const ph=await hashPw(pin);let n=Math.max(0,...(await allEmps(env.DB)).map(e=>+e.employee_no.slice(4)))+1;const out=[];
   for(const name of names){const no='OGI-'+String(n++).padStart(4,'0');await env.DB.prepare('INSERT INTO employees(employee_no,name,pin_hash,active) VALUES(?,?,?,1)').bind(no,name,ph).run();out.push({employeeNo:no,name,active:true,pinHash:true})}
   return {employee:out[0],employees:out}},
 'POST set-pin':async({env,b,s})=>{admin(s);if(String(b.pin||'').length<4)throw bad('Password must be at least 4 characters');
   const r=await env.DB.prepare('UPDATE employees SET pin_hash=? WHERE employee_no=?').bind(await hashPw(b.pin),b.employeeNo).run();if(!r.meta.changes)throw bad('Not found',404);return {ok:true}},
};
export default {async fetch(req,env){
  const u=new URL(req.url),headers=new Headers({'Content-Type':'application/json','Cache-Control':'no-store'});
  const send=(c,o)=>new Response(JSON.stringify(o),{status:c,headers});
  try{
    if(!u.pathname.startsWith('/api/'))return env.ASSETS?env.ASSETS.fetch(req):new Response('Not found',{status:404});
    await init(env.DB);
    const key=req.method+' '+u.pathname.slice(5),h=routes[key];if(!h)throw bad('Not found',404);
    const c=cfg(env),s=await session(req,c.SECRET);
    if(!s&&key!=='POST login')throw bad('Not signed in',401);
    const b=req.method==='POST'?await req.json().catch(()=>({})):{};
    return send(200,await h({env,b,s,u,c,headers}));
  }catch(e){return send(e.code||400,{error:e.message||'Error'})}
}};
