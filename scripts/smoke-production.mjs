import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
const base=(process.argv[2] || 'http://127.0.0.1:4005').replace(/\/$/,'');
const report={testedAt:new Date().toISOString(),base,checks:[]};
async function check(path,expected,init={}) {
  const response=await fetch(base+path,{...init,signal:AbortSignal.timeout(15000)});
  report.checks.push({path,status:response.status,expected,passed:response.status===expected});
  assert.equal(response.status,expected,path);
  return response;
}
const config=await (await check('/api/config',200)).json();
assert.equal(config.paymentProvider,'bachs');
assert.deepEqual(config.fundingPlanAmounts,[64000,98550,135000,540000,2160000]);
for(const path of ['/api/admin/overview','/api/admin/investors','/api/admin/payments','/api/support/admin/conversations','/api/investor/dashboard/11111111-1111-4111-8111-111111111111'])await check(path,401);
await check('/api/auth/admin-register',410,{method:'POST'});
await check('/api/admin/dev/seed-investment',410,{method:'POST'});
await check('/api/bachs/webhook',401,{method:'POST',headers:{'Content-Type':'application/json','X-Bachs-Signature':'forged'},body:JSON.stringify({id:'forged-smoke-test',type:'collection.succeeded',data:{}})});
await check('/api/bachs/initiate',400,{method:'POST',headers:{'Content-Type':'application/json'},body:'{broken'});
await check('/api/config',403,{headers:{Origin:'https://unrelated-site.vercel.app'}});
await fs.mkdir('reports',{recursive:true});
await fs.writeFile('reports/backend-smoke-test.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));
