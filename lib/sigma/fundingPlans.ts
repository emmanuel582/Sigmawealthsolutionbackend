export const FUNDING_PLANS = [
  { id: 'ngn-64000', amount: 64_000 },
  { id: 'ngn-98550', amount: 98_550 },
  { id: 'ngn-135000', amount: 135_000 },
  { id: 'ngn-540000', amount: 540_000 },
  { id: 'ngn-2160000', amount: 2_160_000 },
] as const;

export const FUNDING_PLAN_AMOUNTS = FUNDING_PLANS.map(plan => plan.amount);
export const FUNDING_PLAN_ERROR = 'Choose exactly ₦64,000, ₦98,550, ₦135,000, ₦540,000, or ₦2,160,000.';

export function getFundingPlan(value: unknown) {
  if (typeof value !== 'number' && typeof value !== 'string') return undefined;
  if (!/^\d+(?:\.0{1,2})?$/.test(String(value))) return undefined;
  return FUNDING_PLANS.find(plan => plan.amount === Number(value));
}

export function isFundingPlanAmount(value: unknown): boolean {
  return getFundingPlan(value) !== undefined;
}
