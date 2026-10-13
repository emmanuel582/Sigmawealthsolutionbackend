import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
const key=(process.env.BACHS_API_KEY || '').trim();
const base=key.startsWith('sk_sandbox_')?'https://sandbox-api.bachs.io':'https://api.bachs.io';
if(!/^sk_(sandbox|live)_/.test(key)) throw new Error('BACHS_API_KEY is missing or invalid.');
let ready=true;
for(const route of ['/v1/accounts/me','/v1/webhooks/endpoints']) {
  const response=await fetch(base+route,{headers:{Authorization:`Bearer ${key}`},signal:AbortSignal.timeout(20000)});
  const data=await response.json().catch(()=>({}));
  if(route.endsWith('/me')) {
    const connect=data.enabled_capabilities?.includes('connect') || data.capabilities?.connect?.status==='active';
    console.log('Bachs account', {status:response.status,active:data.is_active,connectActive:Boolean(connect),sandbox:key.startsWith('sk_sandbox_')});
    if(!response.ok || !connect) ready=false;
  } else {
    const expected='https://sigmawealthsolutionbackend.onrender.com/api/bachs/webhook';
    const endpoints=data.items || data.endpoints || [];
    console.log('Bachs webhook', {status:response.status,matchingEndpoints:endpoints.filter(e=>e.url===expected).map(e=>({enabled:e.enabled,eventSource:e.event_source,events:e.event_types})),secretPresent:Boolean(process.env.BACHS_WEBHOOK_SECRET)});
    if(!response.ok || !endpoints.some(e=>e.url===expected && e.enabled && e.event_source==='all')) ready=false;
  }
}
if(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  const db=createClient(process.env.NEXT_PUBLIC_SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false}});
  for(const table of ['bachs_requests','bachs_customers','bachs_payout_jobs','bachs_webhook_events','bachs_referral_rewards']) {
    const {error}=await db.from(table).select('*',{head:true,count:'exact'}).limit(0);
    console.log('Database migration',{table,ready:!error,errorCode:error?.code});
    if(error) ready=false;
  }
  const { data:health, error:healthError }=await db.rpc('bachs_storage_health');
  console.log('Financial write protection',{ready:health?.schemaVersion===2 && health?.financialWritesRestricted===true,errorCode:healthError?.code});
  if(healthError || health?.schemaVersion!==2 || !health?.financialWritesRestricted) ready=false;
} else {console.log('Supabase server credentials are missing.');ready=false;}
const businessApproved=process.env.BACHS_BUSINESS_APPROVED==='1';
console.log('Live activation',{businessApproved,automationEnabled:process.env.BACHS_AUTOMATION_ENABLED==='1'});
if(!key.startsWith('sk_sandbox_') && !businessApproved) ready=false;
console.log(ready?'Bachs configuration checks passed. Sandbox money-flow testing is still required.':'Bachs activation is incomplete. Fix the reported configuration before live money movement.');
if(!ready) process.exitCode=1;
