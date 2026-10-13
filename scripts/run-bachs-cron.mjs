const base=(process.env.SIGMA_API_URL || '').replace(/\/$/,'');
const secret=process.env.BACHS_CRON_SECRET || '';
if(!base.startsWith('https://') || !secret) throw new Error('Configure the API URL and runner secret.');
const headers={Authorization:`Bearer ${secret}`,'Content-Type':'application/json'};
const check=await fetch(base+'/api/bachs/readiness',{headers,signal:AbortSignal.timeout(60000)});
const readiness=await check.json().catch(()=>({}));
if(!check.ok) throw new Error('Bachs readiness could not be verified. No money movement was requested.');
if(!readiness.businessApproved || !readiness.connectActive || !readiness.automationEnabled || !readiness.databaseReady || !readiness.webhookConfigured) {
  console.log('Bachs runner remains disabled: approval or setup is incomplete.');
  process.exit(0);
}
for(const route of ['/api/investor/auto-debit-reminders','/api/investor/process-auto-debits','/api/payouts/run-cron']) {
  const response=await fetch(base+route,{method:'POST',headers,body:'{}',signal:AbortSignal.timeout(240000)});
  const result=await response.json().catch(()=>({}));
  console.log(route,response.status,{processed:result.processed,successful:result.successfulTransfers,pending:result.pendingTransfers,failed:result.failedTransfers});
  // Never automatically retry a money-moving POST after an uncertain response.
  if(!response.ok || Number(result.failedTransfers)>0) throw new Error('Inspect the API/provider records before retrying this run.');
}
