import { BachsError } from './bachsPayments.js';

const MAX = BigInt(Number.MAX_SAFE_INTEGER);
export function minorUnits(value: unknown, allowZero = false): bigint {
  if ((typeof value !== 'string' && typeof value !== 'number') || String(value).length > 32) throw new BachsError('Invalid monetary amount.',400);
  const text=String(value).trim();
  if (!/^\d+(\.\d{1,2})?$/.test(text)) throw new BachsError('Amount must have at most two decimal places.',400);
  const [whole,fraction='']=text.split('.');
  const result=BigInt(whole)*100n+BigInt(fraction.padEnd(2,'0'));
  if(result>MAX || (allowZero?result<0n:result<=0n))throw new BachsError('Amount is outside the supported range.',400);
  return result;
}
export function majorUnits(value: bigint): string {
  if(value<0n || value>MAX)throw new BachsError('Amount is outside the supported range.',400);
  return String(value/100n)+'.'+String(value%100n).padStart(2,'0');
}
export function payoutAmount(principal: unknown, finalWeek: boolean, rate: unknown): string {
  const units=minorUnits(principal);
  const text=String(rate);
  if(!/^(?:0(?:\.\d{1,6})?|1(?:\.0{1,6})?)$/.test(text))throw new BachsError('The payout interest rate is invalid.',409);
  const [whole,fraction='']=text.split('.');
  const millionths=BigInt(whole)*1_000_000n+BigInt(fraction.padEnd(6,'0'));
  // Round half up once, at the minor-unit boundary.
  const numerator=units*(250_000n+(finalWeek?millionths:0n));
  return majorUnits((numerator+500_000n)/1_000_000n);
}
