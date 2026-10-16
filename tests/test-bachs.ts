import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import express from 'express';
import { decimalAmount, verifyBachsSignature, bachsRequest, BachsError } from '../server/lib/bachsPayments.js';
import { mountBachsRoutes } from '../server/lib/bachsRoutes.js';
import { hasPlatformPayoutCapabilities, isPlatformConnectReady } from '../server/lib/bachsCapabilities.js';
import { FUNDING_PLAN_AMOUNTS, isFundingPlanAmount } from '../lib/sigma/fundingPlans.js';
import { mountAuthorization, secretMatches } from '../server/lib/authorization.js';

test('Bachs signature verifies raw bytes, rejects tampering/stale/future events, and accepts rotated v2 secrets', () => {
  const raw=Buffer.from('{ "id": "evt_test", "data": {"amount":"100000.00"} }');
  const now=Date.now();const timestamp=String(Math.floor(now/1000));
  const signature=crypto.createHmac('sha256','test-secret').update(timestamp+'.').update(raw).digest('hex');
  assert.equal(verifyBachsSignature(raw,{timestamp,signature},'test-secret',now),true);
  assert.equal(verifyBachsSignature(Buffer.from('{}'),{timestamp,signature},'test-secret',now),false);
  assert.equal(verifyBachsSignature(raw,{timestamp,signature},'test-secret',now+301000),false);
  assert.equal(verifyBachsSignature(raw,{timestamp:String(Number(timestamp)+600),signature},'test-secret',now),false);
  assert.equal(verifyBachsSignature(raw,{timestamp,signature:'bad'},'test-secret',now),false);
  assert.equal(verifyBachsSignature(raw,{timestamp:'abc',signature},'test-secret',now),false);
  assert.equal(verifyBachsSignature(raw,{signatureV2:`t=${timestamp},v1=${'0'.repeat(64)},v1=${signature}`},'test-secret',now),true);
});

test('exact funding choices reject arbitrary amounts and alternate value types', () => {
  for (const amount of FUNDING_PLAN_AMOUNTS) {
    assert.equal(isFundingPlanAmount(amount), true);
    assert.equal(isFundingPlanAmount(amount.toFixed(2)), true);
    for (const invalid of [amount-1, amount+1, amount-0.01, amount+0.01]) assert.equal(isFundingPlanAmount(invalid), false);
  }
  for (const invalid of [1, 100000, 150000, true, [], {}, '6.4e4', '64000.001', undefined]) assert.equal(isFundingPlanAmount(invalid), false);
});

test('money stays in exact major-unit decimal strings', () => {
  assert.equal(decimalAmount(100000),'100000.00');
  assert.equal(decimalAmount('00100000.50'),'100000.50');
  assert.equal(decimalAmount('0',true),'0.00');
  for(const amount of ['0','-1','1e5','Infinity','NaN','1.001','',undefined,'900719925474100']) assert.throws(()=>decimalAmount(amount));
});

test('provider writes require a durable key and use the correct environment and account scope', async () => {
  const oldFetch=globalThis.fetch; const oldKey=process.env.BACHS_API_KEY;
  const calls:any[]=[];process.env.BACHS_API_KEY='sk_sandbox_test';
  globalThis.fetch=(async (url:any,init:any)=>{calls.push({url,init});return new Response('{"id":"pay_test","status":"pending"}',{status:200});}) as typeof fetch;
  try {
    await assert.rejects(bachsRequest('/v1/payouts',{method:'POST',body:{amount:'100000.00'}}),/idempotency/);
    assert.equal(calls.length,0);
    await bachsRequest('/v1/payouts',{method:'POST',idempotencyKey:'job-1',accountId:'acct_investor',body:{destination:'pd_bank',amount:'100000.00'}});
    assert.equal(calls[0].url,'https://sandbox-api.bachs.io/v1/payouts');
    assert.equal(calls[0].init.headers['X-Account-Id'],'acct_investor');
    assert.equal(calls[0].init.headers['Idempotency-Key'],'job-1');
    assert.equal(JSON.parse(calls[0].init.body).amount,'100000.00');
    globalThis.fetch=(async()=>{throw new Error('network timeout');}) as typeof fetch;
    await assert.rejects(bachsRequest('/v1/payouts',{method:'POST',idempotencyKey:'job-1',body:{amount:'100000.00'}}),e=>e instanceof BachsError && e.code==='OUTCOME_UNKNOWN');
  } finally {globalThis.fetch=oldFetch;if(oldKey===undefined) delete process.env.BACHS_API_KEY;else process.env.BACHS_API_KEY=oldKey;}
});

async function ledger() {
  const db=new PGlite();
  await db.exec(`
    CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role;
    CREATE TABLE admin_allowlist(email text primary key);
    CREATE TABLE notifications(id uuid primary key,title text,body text,audience text,target_user_id uuid,icon text,image_url text,sent_at timestamptz,delivery_status text);
    CREATE TABLE user_roles(user_id uuid primary key,role text);
    CREATE TABLE profiles(id uuid primary key,name text,phone text,email text,total_invested numeric(15,2) default 0,current_phase text,payment_plan_id text,updated_at timestamptz);
    CREATE TABLE bank_details(user_id uuid primary key,account_number text not null,bank_code text not null,bank_name text not null,account_name text);
    CREATE TABLE payments(id uuid primary key default gen_random_uuid(),user_id uuid,amount numeric(15,2),method text,status text,notes text,created_at timestamptz default now());
    CREATE TABLE payouts(id uuid primary key default gen_random_uuid(),user_id uuid,amount numeric(15,2),mode text,status text,processed_by text,notes text,processed_at timestamptz default now());
    CREATE TABLE investments(id uuid primary key default gen_random_uuid(),user_id uuid,amount numeric(15,2),phase text,type text,status text,start_date timestamptz default now(),next_payment_date date,cycle_count integer default 0,created_at timestamptz default now());
  `);
  await db.exec(await fs.readFile(new URL('../supabase/bachs.sql',import.meta.url),'utf8'));
  await db.exec(await fs.readFile(new URL('../supabase/financial-permissions.sql',import.meta.url),'utf8'));
  // The migration must be safe to apply again.
  await db.exec(await fs.readFile(new URL('../supabase/bachs.sql',import.meta.url),'utf8'));
  return db;
}

test('browser roles cannot modify funds, verified banks, roles, or execute credit RPCs', async () => {
  const db=await ledger();
  try {
    for (const role of ['anon','authenticated']) {
      for (const table of ['payments','payouts','investments','bank_details','user_roles','bachs_requests','bachs_payout_jobs']) {
        for (const privilege of ['INSERT','UPDATE','DELETE']) {
          const result=await db.query<any>('SELECT has_table_privilege($1,$2,$3) AS allowed',[role,table,privilege]);
          assert.equal(result.rows[0].allowed,false,`${role} ${privilege} ${table}`);
        }
      }
      assert.equal((await db.query<any>("SELECT has_function_privilege($1,'bachs_credit_payment(text,text)','EXECUTE') AS allowed",[role])).rows[0].allowed,false);
      assert.equal((await db.query<any>("SELECT has_column_privilege($1,'profiles','total_invested','UPDATE') AS allowed",[role])).rows[0].allowed,false);
    }
    assert.equal((await db.query<any>("SELECT has_column_privilege('authenticated','profiles','name','UPDATE') AS allowed")).rows[0].allowed,true);
  } finally { await db.close(); }
});

test('legacy endpoints require real sessions, ownership, allowlisted admins and private support tokens', async () => {
  const db=await ledger();const owner='88888888-8888-4888-8888-888888888888';
  await db.query("INSERT INTO user_roles VALUES($1,'admin')",[owner]);
  const guest='guest-11111111-1111-4111-8111-111111111111';
  const conversations=new Map([['private-chat',{id:'private-chat',guest_id:guest,user_id:null}]]);
  const app=express();app.use(express.json());mountAuthorization(app,localSupabase(db,owner),conversations);
  app.use('/api',(_req,res)=>res.json({passed:true}));
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const base=`http://127.0.0.1:${(server.address() as any).port}`;
  try {
    for (const route of ['/api/admin/overview','/api/admin/investors','/api/support/admin/conversations',`/api/investor/profile/${owner}`,`/api/investor/dashboard/${owner}`]) assert.equal((await fetch(base+route)).status,401,route);
    const headers={Authorization:'Bearer owner'};
    assert.equal((await fetch(base+'/api/admin/overview',{headers})).status,403,'role alone is insufficient');
    assert.equal((await fetch(base+'/api/investor/profile/somebody-else',{headers})).status,403);
    assert.equal((await fetch(base+`/api/investor/profile/${owner}`,{headers})).status,200);
    assert.equal((await fetch(base+'/api/support/conversations/private-chat?as=user')).status,403);
    assert.equal((await fetch(base+'/api/support/conversations/private-chat?as=user',{headers:{'X-Support-Token':guest}})).status,200);
    assert.equal((await fetch(base+'/api/support/conversations/private-chat/messages',{method:'POST',headers:{'Content-Type':'application/json','X-Support-Token':guest},body:JSON.stringify({sender:'admin',content:'forged'})})).status,401);
    assert.equal((await fetch(base+'/api/auth/admin-register',{method:'POST'})).status,410);
    assert.equal((await fetch(base+'/api/admin/dev/seed-investment',{method:'POST',headers})).status,410);
    assert.equal(secretMatches('aa','é'),false,'UTF-8 length differences must not throw');
    await db.query("INSERT INTO admin_allowlist VALUES('owner@example.test')");
    assert.equal((await fetch(base+'/api/admin/overview',{headers})).status,200);
  } finally { await new Promise<void>(resolve=>server.close(()=>resolve()));await db.close(); }
});

test('database credits a webhook/return race once, rejects payment ID reuse and rolls back atomically', async () => {
  const db=await ledger();const user='11111111-1111-4111-8111-111111111111';
  try {
    await db.query('INSERT INTO profiles(id,email) VALUES ($1,$2)',[user,'investor@example.test']);
    await db.query("INSERT INTO bachs_requests(reference,user_id,kind,amount,phase,checkout_id) VALUES ('order-1',$1,'checkout',100000,'Active Plan','chk_1')",[user]);
    await Promise.all([db.query("SELECT bachs_credit_payment('order-1','ch_1')"),db.query("SELECT bachs_credit_payment('order-1','ch_1')")]);
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'100000.00');
    assert.equal((await db.query<any>('SELECT count(*) FROM payments')).rows[0].count,1);
    assert.equal((await db.query<any>('SELECT amount FROM investments')).rows[0].amount,'100000.00');
    await db.query("INSERT INTO bachs_requests(reference,user_id,kind,amount,phase) VALUES ('order-2',$1,'checkout',100000,'Active Plan')",[user]);
    await assert.rejects(db.query("SELECT bachs_credit_payment('order-2','ch_1')"));
    assert.equal((await db.query<any>("SELECT credited FROM bachs_requests WHERE reference='order-2'")).rows[0].credited,false);
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'100000.00');
    const role=await db.query<any>("SELECT has_function_privilege('authenticated','bachs_credit_payment(text,text)','execute') AS can_execute");
    assert.equal(role.rows[0].can_execute,false);
  }finally{await db.close();}
});

test('card setup never increases investment; a pending payout cannot advance its week and confirmed completion advances once', async () => {
  const db=await ledger();const user='22222222-2222-4222-8222-222222222222';
  try {
    await db.query('INSERT INTO profiles(id,email,total_invested) VALUES ($1,$2,100000)',[user,'saved@example.test']);
    await db.query("INSERT INTO investments(user_id,amount,phase,type,status,next_payment_date,cycle_start_date,payout_phase) VALUES ($1,100000,'Plan','one-time','active',current_date,now()-interval '7 days','week1')",[user]);
    await db.query("INSERT INTO bachs_customers(user_id,customer_id) VALUES ($1,'cust_1')",[user]);
    await db.query("INSERT INTO bachs_requests(reference,user_id,kind,amount,phase,monthly_amount,setup_only) VALUES ('setup-1',$1,'checkout',0,'Plan',150000,true)",[user]);
    await db.query("SELECT bachs_credit_payment('setup-1','')");
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'100000.00');
    assert.equal((await db.query<any>('SELECT active,monthly_amount FROM bachs_customers')).rows[0].active,true);
    await db.query("INSERT INTO bachs_payout_jobs(reference,user_id,investment_id,amount,phase,due_date,account_id,destination_id,mode,actor) SELECT 'payout-1',user_id,id,25000,'week1',next_payment_date,'acct_1','pd_1','automatic','Test' FROM investments");
    await assert.rejects(db.query("SELECT bachs_finish_payout('payout-1','successful')"));
    assert.equal((await db.query<any>('SELECT payout_phase FROM investments')).rows[0].payout_phase,'week1');
    await assert.rejects(db.query("INSERT INTO bachs_payout_jobs(reference,user_id,investment_id,amount,phase,due_date,account_id,destination_id,mode,actor) SELECT 'duplicate',user_id,id,25000,'week1',next_payment_date,'acct_1','pd_1','automatic','Test' FROM investments"));
    await db.query("SELECT bachs_record_pending_payout('payout-1','pay_1')");
    assert.equal((await db.query<any>('SELECT status FROM payouts')).rows[0].status,'pending');
    assert.equal((await db.query<any>('SELECT payout_phase FROM investments')).rows[0].payout_phase,'week1');
    await Promise.all([db.query("SELECT bachs_finish_payout('payout-1','successful')"),db.query("SELECT bachs_finish_payout('payout-1','successful')")]);
    assert.equal((await db.query<any>('SELECT payout_phase FROM investments')).rows[0].payout_phase,'week2');
    assert.equal((await db.query<any>('SELECT count(*) FROM payouts')).rows[0].count,1);
    assert.equal((await db.query<any>("SELECT status FROM bachs_payout_jobs WHERE reference='payout-1'")).rows[0].status,'successful');
    await db.query("SELECT bachs_record_pending_payout('payout-1','pay_1')");
    assert.equal((await db.query<any>('SELECT status FROM payouts')).rows[0].status,'successful');
  }finally{await db.close();}
});

test('failed payouts do not advance the investment', async () => {
  const db=await ledger();const user='33333333-3333-4333-8333-333333333333';
  try{
    await db.query('INSERT INTO profiles(id,email) VALUES ($1,$2)',[user,'failed@example.test']);
    await db.query("INSERT INTO investments(user_id,amount,phase,type,status,next_payment_date,payout_phase) VALUES ($1,100000,'Plan','one-time','active',current_date,'week4')",[user]);
    await db.query("INSERT INTO bachs_payout_jobs(reference,user_id,investment_id,amount,phase,due_date,account_id,destination_id,mode,actor,payout_id) SELECT 'failed-1',user_id,id,40000,'week4',next_payment_date,'acct_1','pd_1','automatic','Test','pay_fail' FROM investments");
    await db.query("SELECT bachs_finish_payout('failed-1','failed')");
    assert.equal((await db.query<any>('SELECT payout_phase FROM investments')).rows[0].payout_phase,'week4');
  }finally{await db.close();}
});

test('the existing 5% referral reward is credited only on the first investment and marked paid only on payout completion', async () => {
  const db=await ledger();const referrer='55555555-5555-4555-8555-555555555555';const payer='66666666-6666-4666-8666-666666666666';
  try{
    await db.query('INSERT INTO profiles(id,email) VALUES($1,$2),($3,$4)',[referrer,'referrer@example.test',payer,'payer@example.test']);
    await db.query('UPDATE profiles SET referred_by=$1 WHERE id=$2',[referrer,payer]);
    for(const [reference,payment] of [['first-referral','ch_ref_first'],['second-referral','ch_ref_second']]) {
      await db.query("INSERT INTO bachs_requests(reference,user_id,kind,amount,phase) VALUES($1,$2,'checkout',100000,'Plan')",[reference,payer]);
      await db.query('SELECT bachs_credit_payment($1,$2)',[reference,payment]);
    }
    assert.equal((await db.query<any>('SELECT count(*) FROM bachs_referral_rewards')).rows[0].count,1);
    assert.equal((await db.query<any>('SELECT referral_pending_payout FROM profiles WHERE id=$1',[referrer])).rows[0].referral_pending_payout,'5000.00');
    await db.query("INSERT INTO bachs_payout_jobs(reference,user_id,reward_id,amount,phase,due_date,account_id,destination_id,mode,actor) SELECT 'referral-payout',referrer_id,id,amount,'referral',current_date,'acct_ref','pd_ref','automatic','Test' FROM bachs_referral_rewards");
    await db.query("SELECT bachs_record_pending_payout('referral-payout','pay_ref')");
    assert.equal((await db.query<any>('SELECT referral_pending_payout FROM profiles WHERE id=$1',[referrer])).rows[0].referral_pending_payout,'5000.00');
    await Promise.all([db.query("SELECT bachs_finish_payout('referral-payout','successful')"),db.query("SELECT bachs_finish_payout('referral-payout','successful')")]);
    const profile=(await db.query<any>('SELECT referral_pending_payout,referral_paid_total FROM profiles WHERE id=$1',[referrer])).rows[0];
    assert.equal(profile.referral_pending_payout,'0.00');assert.equal(profile.referral_paid_total,'5000.00');
  }finally{await db.close();}
});

test('payment and payout routes reject unauthenticated calls; invalid webhook signatures cannot mutate the ledger', async () => {
  const app=express();app.use(express.json({verify:(req:any,_res,body)=>{req.rawBody=body;}}));
  const store:any={profiles:new Map(),investments:new Map(),bank_details:new Map(),card_details:new Map(),auto_debit_plans:new Map(),payments:[],payouts:[],platform_settings:{payout_mode:'automatic'}};
  mountBachsRoutes(app,null,store);
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const address=server.address() as any;const base=`http://127.0.0.1:${address.port}`;
  const oldSecret=process.env.BACHS_WEBHOOK_SECRET;process.env.BACHS_WEBHOOK_SECRET='test-secret';
  try{
    for(const route of ['/api/bachs/initiate','/api/bachs/verify','/api/admin/payouts/manual-pay','/api/payouts/run-cron']) {
      const response=await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
      assert.equal(response.status,401,route);
    }
    const webhook=await fetch(base+'/api/bachs/webhook',{method:'POST',headers:{'Content-Type':'application/json','X-Bachs-Signature':'bad'},body:'{"id":"forged","type":"collection.succeeded","data":{}}'});
    assert.equal(webhook.status,401);assert.equal(store.payments.length,0);assert.equal(store.payouts.length,0);
  }finally{await new Promise<void>(resolve=>server.close(()=>resolve()));if(oldSecret===undefined)delete process.env.BACHS_WEBHOOK_SECRET;else process.env.BACHS_WEBHOOK_SECRET=oldSecret;}
});

// Adapt the real isolated Postgres ledger to the small Supabase query surface used by checkout.
function localSupabase(db: PGlite, userId: string): any {
  const quoted=(name:string)=>{assert.match(name,/^[a-z_]+$/);return '"'+name+'"';};
  return {
    auth:{getUser:async(token:string)=>({data:{user:token==='owner'?{id:userId,email:'owner@example.test',email_confirmed_at:new Date().toISOString()}:null},error:token==='owner'?null:{message:'invalid'}})},
    rpc:async(name:string,args:any={})=>{
      try{const values=Object.values(args);const result=await db.query<any>(`SELECT ${quoted(name)}(${values.map((_,i)=>'$'+(i+1)).join(',')}) AS result`,values);return {data:result.rows[0].result,error:null};}
      catch(error:any){return{data:null,error:{code:error.code}};}
    },
    from:(table:string)=>{
      let method='select',fields='*',payload:any,filters:any[]=[],order='',limit='',single=false,upsert=false;
      const query:any={
        select:(value='*')=>{fields=value;return query;},
        insert:(value:any)=>{method='insert';payload=value;return query;},
        upsert:(value:any)=>{method='insert';payload=value;upsert=true;return query;},
        update:(value:any)=>{method='update';payload=value;return query;},
        eq:(column:string,value:any)=>{filters.push({column,value,operator:'='});return query;},
        not:(column:string,operator:string,value:any)=>{assert.equal(operator,'is');assert.equal(value,null);filters.push({column,operator:'IS NOT NULL'});return query;},
        order:(column:string,opts:any)=>{order=` ORDER BY ${quoted(column)} ${opts.ascending?'ASC':'DESC'}`;return query;},
        limit:(value:number)=>{limit=` LIMIT ${Number(value)}`;return query;},
        maybeSingle:()=>{single=true;return query;},single:()=>{single=true;return query;},
        then:(resolve:any,reject:any)=>{
          const run=async()=>{
            try{
              let values:any[]=[],sql='';const returned=fields==='*'?'*':fields.split(',').map(quoted).join(',');
              if(method==='insert'){
                const keys=Object.keys(payload);values=Object.values(payload);
                sql=`INSERT INTO ${quoted(table)} (${keys.map(quoted).join(',')}) VALUES (${keys.map((_,i)=>'$'+(i+1)).join(',')})`;
                if(upsert)sql+=` ON CONFLICT (user_id) DO UPDATE SET ${keys.map(k=>`${quoted(k)}=EXCLUDED.${quoted(k)}`).join(',')}`;
                sql+=` RETURNING ${returned}`;
              }else{
                if(method==='update'){values=Object.values(payload);sql=`UPDATE ${quoted(table)} SET ${Object.keys(payload).map((k,i)=>`${quoted(k)}=$${i+1}`).join(',')}`;}
                else sql=`SELECT ${returned} FROM ${quoted(table)}`;
                if(filters.length)sql+=' WHERE '+filters.map(f=>{if(f.operator==='IS NOT NULL')return quoted(f.column)+' IS NOT NULL';values.push(f.value);return `${quoted(f.column)} = $${values.length}`;}).join(' AND ');
                if(method==='update')sql+=` RETURNING ${returned}`;else sql+=order+limit;
              }
              const result=await db.query<any>(sql,values);
              return {data:single?result.rows[0] || null:result.rows,error:null};
            }catch(error:any){return{data:null,error:{code:error.code}};}
          };
          return run().then(resolve,reject);
        },
      };
      return query;
    },
  };
}

test('hosted checkout, verified return and webhook credit only the stored owner and amount; repeated delivery cannot double-credit', async () => {
  const db=await ledger();const user='44444444-4444-4444-8444-444444444444';
  await db.query('INSERT INTO profiles(id,email,name) VALUES($1,$2,$3)',[user,'owner@example.test','Owner']);
  const app=express();app.use(express.json({verify:(req:any,_res,raw)=>{req.rawBody=raw;}}));
  const store:any={profiles:new Map(),investments:new Map(),bank_details:new Map(),card_details:new Map(),auto_debit_plans:new Map(),payments:[],payouts:[],platform_settings:{payout_mode:'manual'}};
  mountBachsRoutes(app,localSupabase(db,user),store);
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const base=`http://127.0.0.1:${(server.address() as any).port}`;
  const realFetch=globalThis.fetch;const oldKey=process.env.BACHS_API_KEY;const oldSecret=process.env.BACHS_WEBHOOK_SECRET;
  process.env.BACHS_API_KEY='sk_sandbox_test';process.env.BACHS_WEBHOOK_SECRET='test-secret';
  const sessions=new Map<string,any>();let checkoutCounter=0;let insecureCheckout=false;
  const response=(data:any,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
  globalThis.fetch=(async (url:any,options:any)=>{
    if(String(url).startsWith(base))return realFetch(url,options);
    assert.ok(String(url).startsWith('https://sandbox-api.bachs.io/'),'tests must never call live Bachs');
    const endpoint=new URL(String(url)).pathname;
    if(endpoint==='/v1/accounts/checkout/settings')return response({fee_preference:'org_pays'});
    if(endpoint==='/v1/customers')return response({customer_id:'cust_owner'});
    if(endpoint==='/v1/checkout-sessions'){
      const body=JSON.parse(options.body);const id='chk_'+(++checkoutCounter);
      if(body.pricing){assert.ok(isFundingPlanAmount(body.pricing.amount));assert.equal(body.pricing.currency,'NGN');}
      else assert.equal(body.save_payment_method,true);
      sessions.set(id,{checkout_id:id,reference:body.reference,amount:body.pricing?.amount || '0.00',mode:body.pricing?'payment':'setup',currency:'NGN',status:'open',payment_status:'unpaid',charge:{payment_id:'ch_'+checkoutCounter}});
      return response({checkout_id:id,checkout_url:(insecureCheckout?'http://':'https://')+'sandbox-checkout.bachs.io/c/'+id});
    }
    if(endpoint.startsWith('/v1/checkout-sessions/'))return response(sessions.get(endpoint.split('/').at(-1)!));
    throw new Error('Unexpected provider call in checkout test: '+endpoint);
  }) as typeof fetch;
  const post=(route:string,body:any)=>fetch(base+route,{method:'POST',headers:{Authorization:'Bearer owner','Content-Type':'application/json'},body:JSON.stringify(body)});
  try{
    assert.equal((await post('/api/bachs/initiate',{userId:'someone-else',amount:64000})).status,403);
    assert.equal((await post('/api/bachs/initiate',{userId:user,amount:50000})).status,400);
    for(const amount of FUNDING_PLAN_AMOUNTS) {
      for(const invalid of [amount-1,amount+1,amount-0.01,amount+0.01]) {
        assert.equal((await post('/api/bachs/initiate',{userId:user,amount:invalid,phase:'Plan'})).status,400);
      }
      assert.equal((await post('/api/investor/auto-debit-plan',{userId:user,amount:amount+1})).status,400);
    }
    assert.equal(checkoutCounter,0,'invalid amounts must not call Bachs');
    assert.equal((await post('/api/bachs/initiate',{userId:user,amount:64000,monthlyPlanAmount:98550,isRecurringPlan:true})).status,400);
    assert.equal(checkoutCounter,0,'mismatched monthly plans must not create a checkout');
    const started=await post('/api/bachs/initiate',{userId:user,amount:64000,monthlyPlanAmount:64000,isRecurringPlan:true,phase:'Plan'});
    assert.equal(started.status,200);const checkout=await started.json();
    assert.equal(checkout.amountCharged,64000,'first monthly enrollment charges exactly the selected plan');
    for(const amount of FUNDING_PLAN_AMOUNTS) {
      const response=await post('/api/bachs/initiate',{userId:user,amount,phase:'Plan'});
      assert.equal(response.status,200);assert.equal((await response.json()).amountCharged,amount);
    }
    const pending=await post('/api/bachs/verify',{userId:user,sessionId:checkout.sessionId,txRef:checkout.reference});
    assert.equal(pending.status,202);assert.equal((await pending.json()).success,false);
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'0.00');
    const session=sessions.get(checkout.sessionId);session.status='completed';
    for (const status of ['requires_payment_method','requires_confirmation','requires_action','processing','failed','canceled']) {
      session.payment_status=status;
      assert.equal((await post('/api/bachs/verify',{userId:user,sessionId:checkout.sessionId,txRef:checkout.reference})).status,409);
      assert.equal((await db.query<any>('SELECT count(*) FROM payments')).rows[0].count,0,'incomplete payments must never be credited');
    }
    session.payment_status='succeeded';
    Object.assign(session.charge,{status:'succeeded',amount:'64000.00',amount_paid:'64000.00',amount_remaining:'0.00',currency:'NGN',reference:checkout.reference});
    const raw=Buffer.from(JSON.stringify({id:'evt_checkout_test',type:'collection.succeeded',data:{checkout_id:checkout.sessionId}}));
    const timestamp=String(Math.floor(Date.now()/1000));const signature=crypto.createHmac('sha256','test-secret').update(timestamp+'.').update(raw).digest('hex');
    const webhook=()=>fetch(base+'/api/bachs/webhook',{method:'POST',headers:{'Content-Type':'application/json','X-Bachs-Timestamp':timestamp,'X-Bachs-Signature':signature},body:raw});
    const [returned,delivered]=await Promise.all([post('/api/bachs/verify',{userId:user,sessionId:checkout.sessionId,txRef:checkout.reference,amount:999999999,phase:'tampered'}),webhook()]);
    assert.equal(returned.status,200);assert.equal(delivered.status,200);
    assert.equal((await returned.json()).payment.amount,64000);
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'64000.00');
    assert.equal((await db.query<any>('SELECT count(*) FROM payments')).rows[0].count,1);
    assert.equal((await webhook()).status,200);
    assert.equal((await db.query<any>('SELECT count(*) FROM payments')).rows[0].count,1);
    const next=await (await post('/api/bachs/initiate',{userId:user,amount:64000,phase:'Plan'})).json();
    Object.assign(sessions.get(next.sessionId),{status:'completed',payment_status:'succeeded',amount:'63999.00'});
    assert.equal((await post('/api/bachs/verify',{userId:user,sessionId:next.sessionId,txRef:next.reference})).status,409);
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'64000.00');
    const setup=await (await post('/api/bachs/initiate',{userId:user,amount:98550,monthlyPlanAmount:98550,isRecurringPlan:true,phase:'Plan'})).json();
    assert.equal(setup.amountCharged,0);assert.equal(setup.monthlyPlanAmount,98550);
    Object.assign(sessions.get(setup.sessionId),{status:'completed',payment_status:'no_payment_required'});
    const saved=await post('/api/bachs/verify',{userId:user,sessionId:setup.sessionId,txRef:setup.reference});
    assert.equal(saved.status,200);
    assert.equal((await db.query<any>('SELECT total_invested FROM profiles')).rows[0].total_invested,'64000.00');
    assert.equal((await db.query<any>('SELECT monthly_amount FROM bachs_customers')).rows[0].monthly_amount,'98550.00');
    insecureCheckout=true;assert.equal((await post('/api/bachs/initiate',{userId:user,amount:64000,phase:'Plan'})).status,502,'unsafe provider redirects are rejected');
  }finally{
    globalThis.fetch=realFetch;
    if(oldKey===undefined)delete process.env.BACHS_API_KEY;else process.env.BACHS_API_KEY=oldKey;
    if(oldSecret===undefined)delete process.env.BACHS_WEBHOOK_SECRET;else process.env.BACHS_WEBHOOK_SECRET=oldSecret;
    await new Promise<void>(resolve=>server.close(()=>resolve()));await db.close();
  }
});

test('a bank payout includes its fee, stays pending until delivery and cannot be sent twice', async () => {
  const db=await ledger();const user='77777777-7777-4777-8777-777777777777';
  await db.query('INSERT INTO profiles(id,email,total_invested) VALUES($1,$2,100000)',[user,'owner@example.test']);
  await db.query("INSERT INTO user_roles(user_id,role) VALUES($1,'admin')",[user]);
  await db.query("INSERT INTO admin_allowlist(email) VALUES('owner@example.test')");
  await db.query("INSERT INTO investments(user_id,amount,phase,type,status,next_payment_date,cycle_start_date,payout_phase) VALUES($1,100000,'Plan','one-time','active',current_date,now()-interval '7 days','week1')",[user]);
  await db.query("INSERT INTO bank_details(user_id,account_name,bachs_account_id,country,currency) VALUES($1,'Owner','acct_owner','NG','NGN')",[user]);
  const app=express();app.use(express.json({verify:(req:any,_res,raw)=>{req.rawBody=raw;}}));
  const store:any={profiles:new Map(),investments:new Map(),bank_details:new Map(),card_details:new Map(),auto_debit_plans:new Map(),payments:[],payouts:[],platform_settings:{payout_mode:'manual',interest_rate:0.15}};
  mountBachsRoutes(app,localSupabase(db,user),store);
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const base=`http://127.0.0.1:${(server.address() as any).port}`;
  const realFetch=globalThis.fetch;const oldKey=process.env.BACHS_API_KEY;const oldSecret=process.env.BACHS_WEBHOOK_SECRET;
  process.env.BACHS_API_KEY='sk_sandbox_test';process.env.BACHS_WEBHOOK_SECRET='test-secret';
  let transfers=0,payouts=0;let remote:any;let approved=false;
  globalThis.fetch=(async(url:any,options:any)=>{
    if(String(url).startsWith(base))return realFetch(url,options);
    assert.ok(String(url).startsWith('https://sandbox-api.bachs.io/'));
    const endpoint=new URL(String(url)).pathname;
    const json=(data:any)=>new Response(JSON.stringify(data),{status:200});
    if(endpoint==='/v1/accounts/acct_owner')return json({enabled_capabilities:['transfers','payouts']});
    if(endpoint==='/v1/payouts/destinations')return json({items:[{id:'pd_owner',currency:'NGN',is_default:true,is_usable:approved,account_name:'Owner',account_number:'0123456789',bank_name:'Test Bank'}]});
    if(endpoint==='/v1/payouts/quotes'){
      assert.equal(options.headers['X-Account-Id'],'acct_owner');const body=JSON.parse(options.body);
      return json({from_amount:body.amount,to_amount:(Number(body.amount)-100).toFixed(2)});
    }
    if(endpoint==='/v1/transfers'){
      transfers++;const body=JSON.parse(options.body);assert.equal(body.amount,'25100.00');assert.equal(body.currency,'NGN');assert.equal(body.destination,'acct_owner');
      return json({id:'tr_1',status:'paid'});
    }
    if(endpoint==='/v1/payouts'){
      payouts++;const body=JSON.parse(options.body);assert.equal(body.amount,'25000.00');assert.equal(body.destination,'pd_owner');assert.equal(options.headers['X-Account-Id'],'acct_owner');
      remote={...body,id:'pay_bank',status:'pending'};return json(remote);
    }
    if(endpoint==='/v1/payouts/pay_bank')return json(remote);
    throw new Error('Unexpected provider operation: '+endpoint);
  }) as typeof fetch;
  const pay=()=>fetch(base+'/api/admin/payouts/manual-pay',{method:'POST',headers:{Authorization:'Bearer owner','Content-Type':'application/json'},body:JSON.stringify({userId:user,referenceNote:'Test payout'})});
  try{
    for(const amount of [0,1,25001]) { const response=await fetch(base+'/api/admin/payouts/manual-pay',{method:'POST',headers:{Authorization:'Bearer owner','Content-Type':'application/json'},body:JSON.stringify({userId:user,amount,referenceNote:'Invalid amount'})});assert.equal(response.status,400); }
    assert.equal(transfers,0);assert.equal(payouts,0);
    assert.equal((await pay()).status,409);assert.equal(transfers,0);assert.equal(payouts,0);
    approved=true;
    const first=await pay();assert.equal(first.status,200);assert.equal((await first.json()).status,'pending');
    assert.equal((await db.query<any>('SELECT payout_phase FROM investments')).rows[0].payout_phase,'week1');
    assert.equal((await db.query<any>('SELECT status FROM payouts')).rows[0].status,'pending');
    assert.equal((await pay()).status,200);assert.equal(transfers,1);assert.equal(payouts,1);
    remote.status='completed';
    const timestamp=String(Math.floor(Date.now()/1000));const raw=Buffer.from(JSON.stringify({id:'evt_payout_test',type:'payout.paid',account:'acct_owner',organization_id:'acct_owner',data:{reference:remote.reference,id:remote.id}}));
    const signature=crypto.createHmac('sha256','test-secret').update(timestamp+'.').update(raw).digest('hex');
    const webhook=()=>fetch(base+'/api/bachs/webhook',{method:'POST',headers:{'Content-Type':'application/json','X-Bachs-Timestamp':timestamp,'X-Bachs-Signature':signature},body:raw});
    assert.equal((await webhook()).status,200);assert.equal((await webhook()).status,200);
    assert.equal((await db.query<any>('SELECT payout_phase FROM investments')).rows[0].payout_phase,'week2');
    assert.equal((await db.query<any>('SELECT count(*) FROM payouts')).rows[0].count,1);
    assert.equal((await db.query<any>('SELECT status FROM payouts')).rows[0].status,'successful');
    assert.equal(transfers,1);assert.equal(payouts,1);
  }finally{
    globalThis.fetch=realFetch;
    if(oldKey===undefined)delete process.env.BACHS_API_KEY;else process.env.BACHS_API_KEY=oldKey;
    if(oldSecret===undefined)delete process.env.BACHS_WEBHOOK_SECRET;else process.env.BACHS_WEBHOOK_SECRET=oldSecret;
    await new Promise<void>(resolve=>server.close(()=>resolve()));await db.close();
  }
});

test('day-before recurring reminders persist once across simultaneous runs and ignore legacy amounts',async()=>{
  const db=await ledger();const owner='99999999-9999-4999-8999-999999999999';const legacy='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const tomorrow=new Date(Date.now()+86400000).toISOString().slice(0,10);
  await db.query('INSERT INTO profiles(id,email) VALUES($1,$2),($3,$4)',[owner,'owner@example.test',legacy,'legacy@example.test']);
  await db.query("INSERT INTO user_roles VALUES($1,'admin')",[owner]);await db.query("INSERT INTO admin_allowlist VALUES('owner@example.test')");
  await db.query('INSERT INTO bachs_customers(user_id,customer_id,payment_method_id,monthly_amount,next_charge_date,active) VALUES($1,$2,$3,64000,$4,true),($5,$6,$7,100000,$4,true)',[owner,'cust_reminder','pm_reminder',tomorrow,legacy,'cust_legacy','pm_legacy']);
  const app=express();app.use(express.json());
  const store:any={profiles:new Map(),investments:new Map(),bank_details:new Map(),card_details:new Map(),auto_debit_plans:new Map(),notifications:[],payments:[],payouts:[],platform_settings:{payout_mode:'manual'}};
  mountBachsRoutes(app,localSupabase(db,owner),store);
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
  const base='http://127.0.0.1:'+(server.address() as any).port;const oldKey=process.env.BACHS_API_KEY;process.env.BACHS_API_KEY='sk_sandbox_test';
  try {
    const send=()=>fetch(base+'/api/investor/auto-debit-reminders',{method:'POST',headers:{Authorization:'Bearer owner','Content-Type':'application/json'},body:'{}'});
    const results=await Promise.all([send(),send()]);for(const response of results)assert.equal(response.status,200);
    const counts=await Promise.all(results.map(async r=>(await r.json()).sent));assert.deepEqual(counts.sort(),[0,1]);
    const rows=(await db.query<any>('SELECT * FROM notifications')).rows;assert.equal(rows.length,1);assert.equal(rows[0].target_user_id,owner);assert.match(rows[0].body,/64,000/);assert.match(rows[0].body,/cancel/);
  } finally {if(oldKey===undefined)delete process.env.BACHS_API_KEY;else process.env.BACHS_API_KEY=oldKey;await new Promise<void>(r=>server.close(()=>r()));await db.close();}
});

test('approved platform capabilities and recipient access are checked without an invented connect flag', async () => {
  const approved={is_active:true,enabled_capabilities:['ngn_card_collection','payouts','transfers']};
  assert.equal(hasPlatformPayoutCapabilities(approved),true);
  assert.equal(hasPlatformPayoutCapabilities({...approved,is_active:false}),false);
  assert.equal(hasPlatformPayoutCapabilities({...approved,enabled_capabilities:['payouts']}),false);
  assert.equal(hasPlatformPayoutCapabilities({is_active:true,enabled_capabilities:['connect']}),false);
  const savedFetch=globalThis.fetch;const savedKey=process.env.BACHS_API_KEY;
  process.env.BACHS_API_KEY='sk_sandbox_test';
  try {
    let reads=0;
    globalThis.fetch=(async (url:any,init:any)=>{
      assert.equal(new URL(String(url)).pathname,'/v1/accounts');
      assert.equal(init.method,'GET');reads++;
      return new Response('{"items":[]}',{status:200});
    }) as typeof fetch;
    assert.equal(await isPlatformConnectReady(approved),true);
    assert.equal(reads,1);
    globalThis.fetch=(async()=>new Response('{"message":"Recipient accounts unavailable"}',{status:403})) as typeof fetch;
    assert.equal(await isPlatformConnectReady(approved),false);
    globalThis.fetch=(async()=>new Response('{"message":"Temporary provider failure"}',{status:503})) as typeof fetch;
    await assert.rejects(isPlatformConnectReady(approved));
  } finally {globalThis.fetch=savedFetch;if(savedKey===undefined)delete process.env.BACHS_API_KEY;else process.env.BACHS_API_KEY=savedKey;}
});
