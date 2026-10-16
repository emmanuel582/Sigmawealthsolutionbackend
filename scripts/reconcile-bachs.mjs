// Read-only: never submits charges, transfers, payouts, credits or balance updates.
import assert from 'node:assert/strict';
if(process.argv[2])process.loadEnvFile(process.argv[2]);
const base=(process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim()+'/rest/v1/';
const key=(process.env.BACHS_API_KEY || '').trim();
assert.match(base,/^https:\/\//);assert.ok(process.env.SUPABASE_SERVICE_ROLE_KEY);assert.match(key,/^sk_(live|sandbox)_/);
const provider=key.startsWith('sk_sandbox_')?'https://sandbox-api.bachs.io':'https://api.bachs.io';
async function get(url,headers){const r=await fetch(url,{headers,signal:AbortSignal.timeout(20_000)});if(!r.ok)throw Error('Read failed: HTTP '+r.status);return r.json();}
const headers={apikey:process.env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+process.env.SUPABASE_SERVICE_ROLE_KEY};
const rows=await get(base+'bachs_requests?kind=eq.checkout&order=created_at.desc&limit=50',headers);
function cents(value){const text=String(value);assert.match(text,/^\d+(\.\d{1,2})?$/);const [whole,fraction='']=text.split('.');return BigInt(whole)*100n+BigInt(fraction.padEnd(2,'0'));}
const issues=[];let completed=0,pending=0;
const users=new Set();
for(const row of rows){
  users.add(row.user_id);
  if(!row.checkout_id){issues.push({reference:row.reference,issue:'checkout_id_missing_requires_review'});continue;}
  const session=await get(provider+'/v1/checkout-sessions/'+encodeURIComponent(row.checkout_id),{Authorization:'Bearer '+key});
  const paid=session.status==='completed' && session.payment_status==='succeeded';
  if(paid)completed++;else pending++;
  const payments=await get(base+'payments?provider_reference=eq.'+encodeURIComponent(row.reference)+'&select=amount,status,bachs_payment_id',headers);
  if(session.reference!==row.reference || String(session.currency).toUpperCase()!==row.currency || cents(session.amount)!==cents(row.amount))issues.push({reference:row.reference,issue:'provider_request_mismatch'});
  if(paid && !row.credited)issues.push({reference:row.reference,issue:'paid_but_uncredited'});
  if(row.credited && !row.setup_only && (!paid || payments.length!==1 || payments[0].status!=='successful' || cents(payments[0].amount)!==cents(row.amount) || payments[0].bachs_payment_id!==session.charge?.payment_id))issues.push({reference:row.reference,issue:'credited_ledger_discrepancy'});
}
for(const userId of users){
  let sum=0n;
  for(const [table,filter]of [['payments','status=eq.successful'],['opay_receipts','status=eq.approved']]){
    for(let offset=0;offset<10000;offset+=500){
      const transactions=await get(base+table+'?user_id=eq.'+userId+'&'+filter+'&select=amount&limit=500&offset='+offset,headers);
      for(const transaction of transactions)sum+=cents(transaction.amount);
      if(transactions.length<500)break;
      if(offset===9500)throw Error('Account history exceeds reconciliation batch limit; use a full ledger export.');
    }
  }
  const profiles=await get(base+'profiles?id=eq.'+userId+'&select=total_invested',headers);
  if(profiles.length!==1 || cents(profiles[0].total_invested)!==sum)issues.push({account:userId,issue:'profile_does_not_match_contribution_ledger'});
}
const unsettled=await get(base+'bachs_payout_jobs?status=not.in.(successful,failed)&select=reference,status,transfer_id,payout_id&limit=100',headers);
for(const job of unsettled)if(!job.payout_id)issues.push({reference:job.reference,issue:'unfinished_payout_requires_provider_reconciliation',state:job.status});
console.log(JSON.stringify({readOnly:true,scope:'latest 50 checkout requests',checked:rows.length,completed,pending,issues},null,2));
if(issues.length)process.exitCode=2;
