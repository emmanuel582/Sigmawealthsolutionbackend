export function safeProfileUpdates(value: unknown): Record<string,string> | null {
  if(!value || Array.isArray(value) || typeof value!=='object')return null;
  const entries=Object.entries(value);
  if(!entries.length || entries.some(([key,v])=>!['name','phone'].includes(key) || typeof v!=='string' || v.length>(key==='name'?120:40)))return null;
  return Object.fromEntries(entries.map(([key,v])=>[key,(v as string).trim()]));
}
