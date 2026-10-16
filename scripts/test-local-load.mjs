// Starts only a loopback server with external credentials explicitly disabled.
import { performance } from 'node:perf_hooks';
Object.assign(process.env,{SIGMA_API_NO_LISTEN:'1',NODE_ENV:'production',FORCE_HTTPS:'0',NEXT_PUBLIC_SUPABASE_URL:'',SUPABASE_SERVICE_ROLE_KEY:'',BACHS_API_KEY:'',BACHS_WEBHOOK_SECRET:''});
const {app,startServer}=await import('../dist/sigma-api.js');
await startServer();
const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
const base='http://127.0.0.1:'+server.address().port;
const results=[];let index=0;const start=performance.now();
try {
 await Promise.all(Array.from({length:25},async()=>{
  while(index<600){const task=index++;const health=task%6===0;const t=performance.now();const response=await fetch(base+(health?'/health':'/api/config'));await response.arrayBuffer();results.push({health,status:response.status,ms:performance.now()-t});}
 }));
 const latencies=results.map(r=>r.ms).sort((a,b)=>a-b);
 const failures=results.filter(r=>r.health?r.status!==200:![200,429].includes(r.status));
 console.log(JSON.stringify({environment:'loopback production build; no external credentials',scope:'public config/health only; excludes database and provider latency',requests:results.length,concurrency:25,durationMs:Math.round(performance.now()-start),p95Ms:Math.round(latencies[Math.floor(latencies.length*.95)]),statuses:results.reduce((acc,r)=>(acc[r.status]=(acc[r.status]||0)+1,acc),{}),healthFailures:results.filter(r=>r.health&&r.status!==200).length,unexpectedResponses:failures.length},null,2));
 if(failures.length || results.length!==600)process.exitCode=1;
} finally {server.closeAllConnections();await new Promise(r=>server.close(r));}
