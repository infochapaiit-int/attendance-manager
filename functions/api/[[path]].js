const J=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const LIM={lunch:30,dinner:30,wc:15},LN={lunch:'Lunch Break',dinner:'Dinner Break',wc:'WC Break'};
const hash=async(p,s)=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s+p)))].map(x=>x.toString(16).padStart(2,'0')).join('');
const hm=t=>String(t).split(':').reduce((a,x)=>a*60+ +x,0);
const E=m=>J({error:m},400);

export async function onRequest({request,env}){
 const db=env.DB;
 if(!db)return J({error:'Database not connected. Add a D1 binding named DB.'},500);
 const run=(q,...a)=>db.prepare(q).bind(...a).run();
 const one=(q,...a)=>db.prepare(q).bind(...a).first();
 const all=async(q,...a)=>(await db.prepare(q).bind(...a).all()).results;
 try{
  const path=new URL(request.url).pathname.replace(/^\/api\//,''),now=Date.now();
  const b=request.method==='POST'?await request.json().catch(()=>({})):{};
  const notify=m=>run('INSERT INTO notifications(message,at) VALUES(?,?)',m,now);
  const fine=(s,amt,why)=>run('INSERT INTO fines(staff_id,staff_name,amount,reason,at) VALUES(?,?,?,?,?)',s.id,s.name,amt,why,now);

  if(path==='login'){
   const u=String(b.username||'').trim(),p=String(b.password||'');
   let who=null;
   if(u===(env.ADMIN_USER||'admin')){
    if(!env.ADMIN_PASSWORD)return E('Admin password is not set. Add ADMIN_PASSWORD in Cloudflare settings.');
    if(p===env.ADMIN_PASSWORD)who={role:'admin',name:'Admin',sid:null};
   }else{
    const s=await one('SELECT * FROM staff WHERE username=?',u);
    if(s&&await hash(p,s.salt)===s.pass_hash){
     if(!s.active)return J({error:'This account is deactivated. Contact admin.'},403);
     who={role:'staff',name:s.name,sid:s.id};
    }
   }
   if(!who)return J({error:'Wrong username or password.'},401);
   const t=crypto.randomUUID()+crypto.randomUUID();
   await run('INSERT INTO tokens(token,staff_id,role,at) VALUES(?,?,?,?)',t,who.sid,who.role,now);
   return J({token:t,role:who.role,name:who.name});
  }

  const a=await one('SELECT * FROM tokens WHERE token=?',(request.headers.get('authorization')||'').slice(7));
  if(!a)return J({error:'Session expired. Please log in again.'},401);

  /* ---------- ADMIN ---------- */
  if(a.role==='admin'){
   if(path==='state'){
    return J({now,
     staff:await all('SELECT id,name,role,username,duty_start,duty_end,active FROM staff ORDER BY id'),
     sessions:await all('SELECT s.*,t.name FROM sessions s JOIN staff t ON t.id=s.staff_id ORDER BY s.id DESC LIMIT 100'),
     breaks:await all('SELECT * FROM breaks WHERE session_id IN (SELECT id FROM (SELECT id FROM sessions ORDER BY id DESC LIMIT 100))'),
     fines:await all('SELECT * FROM fines ORDER BY id DESC LIMIT 200'),
     notifs:await all('SELECT * FROM notifications ORDER BY id DESC LIMIT 60'),
     unseen:(await one('SELECT COUNT(*) c FROM notifications WHERE seen=0')).c});
   }
   if(path==='staff/add'||path==='staff/update'){
    const n=String(b.name||'').trim(),u=String(b.username||'').trim(),p=String(b.password||''),role=b.role==='Manager'?'Manager':'Staff';
    if(!n||!u)return E('Name and username are required.');
    if(path==='staff/add'){
     if(p.length<4)return E('Password must be at least 4 characters.');
     const salt=crypto.randomUUID();
     try{await run('INSERT INTO staff(name,role,username,pass_hash,salt,duty_start,duty_end) VALUES(?,?,?,?,?,?,?)',n,role,u,await hash(p,salt),salt,b.duty_start||'10:00',b.duty_end||'22:00')}
     catch(e){return E('Username already exists.')}
    }else{
     if(u===(env.ADMIN_USER||'admin'))return E('This username is reserved.');
     try{await run('UPDATE staff SET name=?,role=?,username=?,duty_start=?,duty_end=? WHERE id=?',n,role,u,b.duty_start||'10:00',b.duty_end||'22:00',b.id)}
     catch(e){return E('Username already exists.')}
     if(p){
      if(p.length<4)return E('Password must be at least 4 characters.');
      const salt=crypto.randomUUID();
      await run('UPDATE staff SET pass_hash=?,salt=? WHERE id=?',await hash(p,salt),salt,b.id);
      await run('DELETE FROM tokens WHERE staff_id=?',b.id);
     }
    }
    return J({ok:1});
   }
   if(path==='staff/toggle'){
    await run('UPDATE staff SET active=1-active WHERE id=?',b.id);
    await run('DELETE FROM tokens WHERE staff_id=? AND staff_id IN (SELECT id FROM staff WHERE active=0)',b.id);
    return J({ok:1});
   }
   if(path==='fine/update'){
    const amt=Math.round(+b.amount);
    if(!(amt>=0))return E('Enter a valid amount.');
    await run('UPDATE fines SET amount=?,reason=? WHERE id=?',amt,String(b.reason||'').trim(),b.id);
    return J({ok:1});
   }
   if(path==='fine/delete'){await run('DELETE FROM fines WHERE id=?',b.id);return J({ok:1})}
   if(path==='fine/reset'){
    if(b.staff_id)await run('DELETE FROM fines WHERE staff_id=?',b.staff_id);else await run('DELETE FROM fines');
    return J({ok:1});
   }
   if(path==='notif/seen'){await run('UPDATE notifications SET seen=1');return J({ok:1})}
   return J({error:'Not found'},404);
  }

  /* ---------- STAFF ---------- */
  const s=await one('SELECT * FROM staff WHERE id=?',a.staff_id);
  if(!s||!s.active)return J({error:'Account deactivated.'},401);
  const cur=await one('SELECT * FROM sessions WHERE staff_id=? AND punch_out IS NULL',s.id);
  const ob=cur&&await one('SELECT * FROM breaks WHERE session_id=? AND ended IS NULL',cur.id);

  if(path==='me'){
   const br=cur?await all('SELECT * FROM breaks WHERE session_id=?',cur.id):[];
   return J({now,name:s.name,duty_start:s.duty_start,duty_end:s.duty_end,session:cur?{...cur,breaks:br}:null,
    fines:await all('SELECT * FROM fines WHERE staff_id=? ORDER BY id DESC LIMIT 100',s.id)});
  }
  if(path==='punch/in'){
   if(cur)return E('You are already punched in.');
   const last=(await one('SELECT MAX(punch_in) m FROM sessions WHERE staff_id=?',s.id)).m;
   if(last&&now-last<3600000)return E('You cannot punch again yet. '+Math.ceil((3600000-(now-last))/60000)+' minute(s) remaining.');
   const t=new Intl.DateTimeFormat('en-GB',{timeZone:env.TIMEZONE||'Asia/Dhaka',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(now);
   const late=hm(t)>hm(s.duty_start)?1:0;
   await run('INSERT INTO sessions(staff_id,punch_in,late) VALUES(?,?,?)',s.id,now,late);
   if(late)await fine(s,1000,'Late punch in (duty starts '+s.duty_start+')');
   await notify(s.name+' punched in'+(late?' (LATE, Tk 1000 fine)':''));
   return J({ok:1});
  }
  if(!cur)return E('You are not punched in.');
  if(path==='punch/out'){
   if(ob)return E('End your current break first.');
   await run('UPDATE sessions SET punch_out=? WHERE id=?',now,cur.id);
   await notify(s.name+' punched out');
   return J({ok:1});
  }
  if(path==='break/start'){
   if(ob)return E('A break is already running.');
   if(!LIM[b.type])return E('Invalid break type.');
   await run('INSERT INTO breaks(session_id,type,started) VALUES(?,?,?)',cur.id,b.type,now);
   await notify(s.name+' started '+LN[b.type]);
   return J({ok:1});
  }
  if(path==='break/end'){
   if(!ob)return E('No break is running.');
   const mins=(now-ob.started)/60000,lim=LIM[ob.type],took=Math.ceil(mins);
   await run('UPDATE breaks SET ended=? WHERE id=?',now,ob.id);
   if(mins>lim){
    await fine(s,500,LN[ob.type]+' exceeded '+lim+' min limit (took '+took+' min)');
    await notify(s.name+' ended '+LN[ob.type]+' after '+took+' min (over limit, Tk 500 fine)');
   }else await notify(s.name+' ended '+LN[ob.type]+' ('+took+' min)');
   return J({ok:1,fined:mins>lim});
  }
  return J({error:'Not found'},404);
 }catch(e){return J({error:'Server error: '+e.message},500)}
}
