import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { getAllowedOrigins } from '../server/lib/security.js';
import { sanitizeRequestBody } from '../server/lib/sanitize.js';
test('production CORS allows exact configured origins and excludes unrelated preview hosts',()=>{
  const old=process.env.NODE_ENV; process.env.NODE_ENV='production';
  try { const origins=getAllowedOrigins();assert.ok(origins.includes('https://sigmawealthsolution.com'));assert.ok(!origins.includes('http://localhost:3000'));assert.ok(!origins.includes('https://unrelated.vercel.app')); }
  finally { if(old===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=old; }
});
test('request sanitization strips executable markup while preserving text',async()=>{
  const app=express();app.use(express.json());app.use(sanitizeRequestBody);app.post('/',(req,res)=>res.json(req.body));
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
  try { const response=await fetch('http://127.0.0.1:'+(server.address() as any).port,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'<script>alert(1)</script>Hello',nested:{value:'<b>Safe</b>'}})});const body=await response.json();assert.equal(body.name,'Hello');assert.equal(body.nested.value,'Safe'); }
  finally { await new Promise<void>(r=>server.close(()=>r())); }
});
