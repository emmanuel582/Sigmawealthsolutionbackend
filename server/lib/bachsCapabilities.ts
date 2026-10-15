import { BachsError, bachsRequest } from './bachsPayments.js';

type Account = { is_active?: boolean; enabled_capabilities?: string[]; capabilities?: Record<string, { status?: string }> };

export function hasPlatformPayoutCapabilities(account: Account): boolean {
  const enabled = (capability: string) => account.enabled_capabilities?.includes(capability) || account.capabilities?.[capability]?.status === 'active';
  return account.is_active === true && Boolean(enabled('transfers') && enabled('payouts'));
}

// Bachs exposes transfers/payouts in enabled_capabilities, rather than a
// capability called "connect". Also verify permission to manage recipients.
export async function isPlatformConnectReady(account: Account): Promise<boolean> {
  if (!hasPlatformPayoutCapabilities(account)) return false;
  try {
    await bachsRequest('/v1/accounts?limit=1');
    return true;
  } catch (error) {
    if (error instanceof BachsError && [401, 403].includes(error.status)) return false;
    throw error;
  }
}
