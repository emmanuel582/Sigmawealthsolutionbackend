import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { applySecurityMiddleware, getAllowedOrigins, productionErrorHandler } from '../server/lib/security.js';
import { sanitizeRequestBody } from '../server/lib/sanitize.js';
test('production CORS allows exact configured origins and excludes unrelated preview hosts',()=>{
  const old=process.env.NODE_ENV; process.env.NODE_ENV='production';
  try { const origins=getAllowedOrigins();assert.ok(origins.includes('https://sigmawealthsolution.com'));assert.ok(origins.includes('https://www.sigmawealthsolution.com'));assert.ok(!origins.includes('http://localhost:3000'));assert.ok(!origins.includes('https://unrelated.vercel.app')); }
  finally { if(old===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=old; }
});
test('request sanitization strips executable markup while preserving text',async()=>{
  const app=express();app.use(express.json());app.use(sanitizeRequestBody);app.post('/',(req,res)=>res.json(req.body));
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
  try { const response=await fetch('http://127.0.0.1:'+(server.address() as any).port,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'<script>alert(1)</script>Hello',nested:{value:'<b>Safe</b>'}})});const body=await response.json();assert.equal(body.name,'Hello');assert.equal(body.nested.value,'Safe'); }
  finally { await new Promise<void>(r=>server.close(()=>r())); }
});


test('payment preflight and requests accept both production hosts while rejecting unrelated origins',async()=>{
  const keys=['NODE_ENV','FORCE_HTTPS','ALLOWED_ORIGINS','APP_URL','FRONTEND_URL'];
  const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  process.env.NODE_ENV='production';process.env.FORCE_HTTPS='0';
  delete process.env.ALLOWED_ORIGINS;delete process.env.APP_URL;delete process.env.FRONTEND_URL;
  const app=express();applySecurityMiddleware(app);app.use(express.json());
  app.post('/api/bachs/initiate',(_req,res)=>res.status(401).json({message:'Sign in to continue.'}));
  app.use(productionErrorHandler);
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const url='http://127.0.0.1:'+(server.address() as any).port+'/api/bachs/initiate';
  try {
    for(const origin of ['https://sigmawealthsolution.com','https://www.sigmawealthsolution.com']) {
      const preflight=await fetch(url,{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,content-type'}});
      assert.equal(preflight.status,204);assert.equal(preflight.headers.get('access-control-allow-origin'),origin);
      assert.equal(preflight.headers.get('access-control-allow-credentials'),'true');
      const response=await fetch(url,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:'{}'});
      assert.equal(response.status,401);assert.equal(response.headers.get('access-control-allow-origin'),origin);
    }
    for(const origin of ['https://unrelated.vercel.app','https://sigmawealthsolution.com.attacker.example','https://www.sigmawealthsolution.com:444','http://localhost:3000']) {
      const response=await fetch(url,{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST'}});
      assert.equal(response.status,403);assert.equal(response.headers.get('access-control-allow-origin'),null);
    }
    const webhookStyleRequest=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    assert.equal(webhookStyleRequest.status,401);
  } finally {
    await new Promise<void>(resolve=>server.close(()=>resolve()));
    for(const key of keys){if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}
  }
});
