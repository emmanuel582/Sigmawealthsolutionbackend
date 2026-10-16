import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { minorUnits, majorUnits, payoutAmount } from '../server/lib/exactMoney.js';
import { safeProfileUpdates } from '../server/lib/profileUpdates.js';
import { concurrencyGuard } from '../server/lib/traffic.js';
import { applySecurityMiddleware, productionErrorHandler } from '../server/lib/security.js';
import { sanitizeRequestBody } from '../server/lib/sanitize.js';

test('exact money survives decimal boundaries, invalid types and 2000 deterministic fuzz cases',()=>{
  assert.equal(payoutAmount('98550',false,'0.15'),'24637.50');
  assert.equal(payoutAmount('98550',true,'0.15'),'39420.00');
  assert.equal(payoutAmount('0.01',true,'0.25'),'0.01');
  for(const bad of [true,[],[64000],{},null,undefined,'1e5','NaN','Infinity','-0.01','0.001','9'.repeat(10000)])assert.throws(()=>minorUnits(bad));
  for(const bad of ['-0.1','1.01','Infinity','0.1234567',{},null])assert.throws(()=>payoutAmount('64000',true,bad));
  let seed=123456789;
  for(let i=0;i<2000;i++){
    seed=(Math.imul(seed,1664525)+1013904223)>>>0;
    const units=BigInt(seed)+1n;
    assert.equal(minorUnits(majorUnits(units)),units);
    const expected=(units*400000n+500000n)/1000000n;
    assert.equal(minorUnits(payoutAmount(majorUnits(units),true,'0.15'),true),expected);
  }
});

test('admin contact edits cannot overwrite financial fields or prototype state',()=>{
  assert.deepEqual(safeProfileUpdates({name:' Test ',phone:'+234123'}),{name:'Test',phone:'+234123'});
  for(const value of [{total_invested:99999},{referral_earnings:100},{referred_by:'admin'},{id:'other'},{email:'attacker@test.test'},{name:'x',payment_plan_id:'forged'},JSON.parse('{"__proto__":{"admin":true}}'),null,[],{name:{value:'x'}},{name:'x'.repeat(121)}])assert.equal(safeProfileUpdates(value),null);
});

test('a local burst sheds excess load, preserves health access and releases capacity after completion',async()=>{
  const app=express();app.use(concurrencyGuard(8));
  const release:Array<()=>void>=[];
  app.get('/api/slow',(_req,res)=>release.push(()=>{if(!res.headersSent)res.json({ok:true});}));
  app.get('/health',(_req,res)=>res.json({ok:true}));app.get('/api/ready',(_req,res)=>res.json({ok:true}));
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
  const base='http://127.0.0.1:'+(server.address() as any).port;
  try{
    const held=Array.from({length:8},()=>fetch(base+'/api/slow'));
    while(release.length<8)await new Promise(r=>setTimeout(r,5));
    const burst=await Promise.all(Array.from({length:100},()=>fetch(base+'/api/ready')));
    assert.ok(burst.every(r=>r.status===503));assert.ok(burst.every(r=>r.headers.get('retry-after')==='2'));
    assert.equal((await fetch(base+'/health')).status,200);
    for(const finish of release)finish();await Promise.all(held);
    assert.equal((await fetch(base+'/api/ready')).status,200);
  }finally{for(const finish of release)finish();server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));}
});

test('customer rate exhaustion cannot block Bachs webhook deliveries; oversized and deeply nested payloads fail safely',async()=>{
  const keys=['NODE_ENV','FORCE_HTTPS','API_RATE_LIMIT_MAX','PAYMENT_RATE_LIMIT_MAX','WEBHOOK_RATE_LIMIT_MAX'];
  const previous=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
  Object.assign(process.env,{NODE_ENV:'production',FORCE_HTTPS:'0',API_RATE_LIMIT_MAX:'3',PAYMENT_RATE_LIMIT_MAX:'2',WEBHOOK_RATE_LIMIT_MAX:'100'});
  const app=express();applySecurityMiddleware(app);app.use(express.json({limit:'8kb'}));app.use(sanitizeRequestBody);
  app.post('/api/bachs/initiate',(_req,res)=>res.json({ok:true}));
  app.post('/api/bachs/webhook',(_req,res)=>res.status(401).json({message:'Signature required'}));app.use(productionErrorHandler);
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));const base='http://127.0.0.1:'+(server.address() as any).port;
  const post=(path:string,body:unknown)=>fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  try{
    assert.equal((await post('/api/bachs/webhook',{x:'a'.repeat(9000)})).status,413);
    let nested:any={};for(let i=0;i<30;i++)nested={child:nested};
    assert.equal((await post('/api/bachs/webhook',nested)).status,400);
    assert.equal((await post('/api/bachs/initiate',{})).status,200);
    assert.equal((await post('/api/bachs/initiate',{})).status,200);
    assert.equal((await post('/api/bachs/initiate',{})).status,429);
    const delivery=await post('/api/bachs/webhook',{});assert.equal(delivery.status,401);
    assert.equal(delivery.headers.get('cache-control'),'no-store');
  }finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));for(const key of keys){if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}}
});
