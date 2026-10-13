import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
const files=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{encoding:'utf8'}).split('\0').filter(Boolean);
const findings=[];
for(const file of new Set(files)) {
  if(!fs.existsSync(file)||fs.statSync(file).size>2_000_000||! /\.(?:[cm]?[jt]sx?|json|ya?ml|md|txt|sql|toml)$/.test(file))continue;
  const value=fs.readFileSync(file,'utf8');
  if(/(?:sk_(?:live|sandbox)_[A-Za-z0-9]{20,}|whsec_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/.test(value))findings.push(file);
  for(const token of value.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g)||[]) {
    try{if(JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString()).role==='service_role')findings.push(file);}catch{}
  }
}
if(findings.length){console.error('Possible private credentials in repository files:',[...new Set(findings)]);process.exitCode=1;}
else console.log('No private provider keys, service-role JWTs, GitHub tokens, or private-key blocks found in repository source.');
