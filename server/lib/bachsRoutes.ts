import type { Express, Request, Response, NextFunction } from 'express';
import type { SupabaseClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';
import { minorUnits, majorUnits, payoutAmount } from './exactMoney.js';
import { isApprovedAdmin, secretMatches } from './authorization.js';
import { isPlatformConnectReady } from './bachsCapabilities.js';
import { FUNDING_PLAN_AMOUNTS, FUNDING_PLAN_ERROR, getFundingPlan, isFundingPlanAmount } from '../../lib/sigma/fundingPlans.js';
import {
  BachsError, bachsRequest, bachsWebhookSecret, bachsWebhookUrl, decimalAmount,
  frontendUrl, isBachsConfigured, verifyBachsSignature, bachsApiKey,
} from './bachsPayments.js';

type Store = {
  profiles: Map<string, any>; investments: Map<string, any>; bank_details: Map<string, any>;
  card_details: Map<string, any>; auto_debit_plans: Map<string, any>; payments: any[]; payouts: any[];
  platform_settings: { payout_mode: 'automatic' | 'manual'; [key: string]: any };
  [key: string]: any;
};

export function mountBachsRoutes(app: Express, database: SupabaseClient | null, store: Store) {
  function db(): SupabaseClient {
    if (!database) throw new BachsError('Payment storage is unavailable. Configure Supabase and apply supabase/bachs.sql.', 503);
    return database;
  }
  async function query<T = any>(result: PromiseLike<{ data: T; error: any }>): Promise<T> {
    const { data, error } = await result;
    if (error) {
      console.error('[Bachs database]', error.code);
      throw new BachsError('Payment storage could not be updated. Verify the Bachs database migration is applied.', 503, 'STORAGE_ERROR');
    }
    return data;
  }
  const endpoint = (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) => async (req: Request, res: Response, next: NextFunction) => {
    try { await fn(req, res, next); }
    catch (error) {
      const err = error instanceof BachsError ? error : new BachsError('The payment operation could not be completed.');
      console.error('[Bachs]', err.code);
      res.status(err.status).json({ message: err.message, code: err.code });
    }
  };
  async function identity(req: Request, admin = false): Promise<{ id: string; email: string; metadata: Record<string,any> }> {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (!token) throw new BachsError('Sign in to continue.', 401);
    const cached=(req as any).res?.locals.authUser;
    const { data, error } = cached ? {data:{user:cached},error:null} : await db().auth.getUser(token);
    if (error || !data.user) throw new BachsError('Your session has expired. Sign in again.', 401);
    const user = { id: data.user.id, email: data.user.email || '', metadata:data.user.user_metadata || {} };
    if (admin) {
      if (!await isApprovedAdmin(db(), data.user)) throw new BachsError('Administrator access required.', 403);
    } else if (req.body?.userId && req.body.userId !== user.id) {
      throw new BachsError('You can only manage your own payment account.', 403);
    }
    return user;
  }
  async function runner(req: Request) {
    const expected = process.env.BACHS_CRON_SECRET || '';
    const supplied = req.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
    if (secretMatches(expected, supplied)) {
      return { id: 'cron', email: 'Scheduled payout runner', metadata:{} };
    }
    return identity(req, true);
  }
  function requireBusinessApproval() {
    if (!bachsApiKey().startsWith('sk_sandbox_') && process.env.BACHS_BUSINESS_APPROVED !== '1') {
      throw new BachsError('Live payments are awaiting Bachs approval of the business use case. Sandbox testing remains available.',409,'BUSINESS_APPROVAL_REQUIRED');
    }
  }
  async function requireStorageReady() {
    const health = await query(db().rpc('bachs_storage_health'));
    if (health?.schemaVersion !== 2 || !health.financialWritesRestricted) throw new BachsError('Apply the complete Bachs and financial permissions migrations before accepting payments.',503,'STORAGE_NOT_READY');
  }
  async function requireExactCheckoutFees() {
    const settings = await bachsRequest('/v1/accounts/checkout/settings');
    if (settings.fee_preference !== 'org_pays') throw new BachsError('The company must cover Bachs fees so each customer pays exactly their selected plan amount.',409,'EXACT_AMOUNT_FEES_REQUIRED');
  }
  async function requireAutomationReady(user: {id:string}) {
    if (user.id !== 'cron') return;
    requireBusinessApproval();
    if (process.env.BACHS_AUTOMATION_ENABLED !== '1') throw new BachsError('The live scheduled runner is disabled.',409,'AUTOMATION_DISABLED');
    const account = await bachsRequest('/v1/accounts/me');
    if (!await isPlatformConnectReady(account)) {
      throw new BachsError('Bachs Connect setup is incomplete.',409,'CONNECT_NOT_ACTIVE');
    }
  }
  async function profileFor(user: { id: string; email: string; metadata?: Record<string,any> }) {
    let profile = await query(db().from('profiles').select('*').eq('id', user.id).maybeSingle());
    if (!profile) profile = await query(db().from('profiles').insert({ id: user.id, email: user.email, name: user.email.split('@')[0] }).select().single());
    const update:any={};
    if(!profile.referral_code) update.referral_code='SW'+user.id.replaceAll('-','').slice(-8).toUpperCase();
    const referralCode=String(user.metadata?.referral_code || '').trim().toUpperCase();
    if(!profile.referred_by && Number(profile.total_invested || 0)===0 && referralCode) {
      const referrer=await query(db().from('profiles').select('id').eq('referral_code',referralCode).maybeSingle());
      if(referrer && referrer.id!==user.id) update.referred_by=referrer.id;
    }
    if(Object.keys(update).length) profile=await query(db().from('profiles').update(update).eq('id',user.id).select().single());
    store.profiles.set(user.id, profile);
    return profile;
  }
  function remember(result: any) {
    if (result.profile) store.profiles.set(result.profile.id, result.profile);
    if (result.investment) store.investments.set(result.investment.user_id, result.investment);
    for (const [key, value] of [['payments', result.payment], ['payouts', result.payout]] as const) {
      if (value) {
        const list = store[key];
        const index = list.findIndex((r: any) => r.id === value.id);
        if (index < 0) list.unshift(value); else list[index] = value;
      }
    }
    return result;
  }
  async function customerFor(user: { id: string; email: string }, name: string) {
    const saved = await query(db().from('bachs_customers').select('*').eq('user_id', user.id).maybeSingle());
    if (saved) return saved;
    const created = await bachsRequest('/v1/customers', { method: 'POST', body: { email: user.email, name }, idempotencyKey: `customer:${user.id}` });
    return query(db().from('bachs_customers').upsert({ user_id: user.id, customer_id: created.customer_id }).select().single());
  }
  async function requestFor(reference?: string, checkoutId?: string) {
    if (!reference && !checkoutId) throw new BachsError('Checkout ID or reference required.', 400);
    return query(db().from('bachs_requests').select('*').eq(reference ? 'reference' : 'checkout_id', reference || checkoutId).maybeSingle());
  }
  async function settleCheckout(request: any, checkoutId?: string) {
    const id = request.checkout_id || checkoutId;
    if (!id) throw new BachsError('Checkout is still being created. Try syncing again shortly.', 409);
    const session = await bachsRequest(`/v1/checkout-sessions/${encodeURIComponent(id)}`);
    if (session.reference !== request.reference || (session.checkout_id || session.id) !== id) {
      throw new BachsError('The checkout does not match this payment request.', 409);
    }
    if (!request.checkout_id) await query(db().from('bachs_requests').update({ checkout_id: id }).eq('reference', request.reference));
    if (String(session.status).toLowerCase() !== 'completed') return { success: false, status: session.status, message: 'Payment is awaiting confirmation.' };
    let paymentId = session.charge?.payment_id || session.charge?.id || session.charge_id || session.payment_id;
    if (!request.setup_only) {
      if (session.payment_status !== 'succeeded' || String(session.currency).toUpperCase() !== 'NGN' || decimalAmount(session.amount) !== decimalAmount(request.amount)) {
        throw new BachsError('The payment amount, currency, or settlement status does not match.', 409);
      }
      if (session.charge?.amount_paid != null && minorUnits(session.charge.amount_paid,true) !== minorUnits(request.amount)
        || session.charge?.amount_remaining != null && minorUnits(session.charge.amount_remaining,true) !== 0n) {
        throw new BachsError('The payment has not been collected in full.',409,'UNDERPAID');
      }
      if (!paymentId) throw new BachsError('Payment ID is not available yet. Try syncing again shortly.', 409);
    } else if (session.mode !== 'setup' || Number(session.amount) !== 0) {
      throw new BachsError('The saved-card setup could not be confirmed.', 409);
    }
    const result = remember(await query(db().rpc('bachs_credit_payment', { p_reference: request.reference, p_payment_id: paymentId || '' })));
    if(result.newCredit)console.info(JSON.stringify({event:'payment_credited',reference:request.reference,userId:request.user_id,amount:decimalAmount(request.amount),currency:'NGN'}));
    await refreshCard(request.user_id);
    return { ...result, success: true, message: request.setup_only ? 'Saved-card setup confirmed.' : 'Bachs payment confirmed and credited.' };
  }
  async function refreshCard(userId: string) {
    const saved = await query(db().from('bachs_customers').select('*').eq('user_id', userId).maybeSingle());
    if (!saved) return;
    if (saved.card_details) store.card_details.set(userId, { ...saved.card_details, user_id: userId, bachs_payment_method_id: saved.payment_method_id, bachs_customer_id: saved.customer_id });
    if (saved.monthly_amount) store.auto_debit_plans.set(userId, {
      user_id: userId, amount: Number(saved.monthly_amount), active: saved.active, next_charge_date: saved.next_charge_date,
      reminder_date: saved.next_charge_date ? new Date(new Date(saved.next_charge_date).getTime() - 86400000).toISOString().slice(0,10) : null,
    });
  }
  async function payoutAccount(userId: string) {
    const bank = await query(db().from('bank_details').select('*').eq('user_id', userId).maybeSingle());
    if (!bank?.bachs_account_id) throw new BachsError('Complete Bachs bank onboarding before receiving payouts.', 409);
    const accountId = bank.bachs_account_id;
    const account = await bachsRequest(`/v1/accounts/${encodeURIComponent(accountId)}`);
    const usable = (cap: string) => account.capabilities?.[cap]?.status === 'active' || account.enabled_capabilities?.includes(cap);
    const list = await bachsRequest('/v1/payouts/destinations?limit=100', { accountId });
    const destinations = list.items || list.destinations || [];
    const destination = destinations.find((d: any) => d.id === bank.bachs_destination_id && d.is_usable)
      || destinations.find((d: any) => d.is_default && d.is_usable && d.currency === 'NGN');
    const ready = Boolean(usable('transfers') && usable('payouts') && destination?.currency === 'NGN');
    const updated = { ...bank, connect_onboarding_complete: ready, payouts_enabled: ready,
      bachs_destination_id: destination?.id || null,
      account_number: destination?.account_number || bank.account_number,
      bank_name: destination?.bank_name || bank.bank_name,
      account_name: destination?.account_name || bank.account_name,
    };
    await query(db().from('bank_details').update(updated).eq('user_id', userId));
    store.bank_details.set(userId, updated);
    if (!ready) throw new BachsError('Bachs identity verification, transfers and payouts capabilities, and an approved NGN default bank destination are required.', 409);
    return { accountId, destination, bank: updated };
  }
  async function reconcileJob(job: any) {
    if (!job.payout_id) return job;
    const remote = await bachsRequest(`/v1/payouts/${encodeURIComponent(job.payout_id)}`, { accountId: job.account_id });
    if (remote.reference !== job.reference || remote.destination !== job.destination_id || decimalAmount(remote.amount) !== decimalAmount(job.amount)) {
      throw new BachsError('Payout reconciliation mismatch. Contact support.', 409);
    }
    const status = String(remote.status).toLowerCase();
    if (status === 'completed' || status === 'paid') {
      return remember(await query(db().rpc('bachs_finish_payout', { p_reference: job.reference, p_status: 'successful' })));
    }
    if (status === 'failed' || status === 'rejected') {
      return remember(await query(db().rpc('bachs_finish_payout', { p_reference: job.reference, p_status: 'failed' })));
    }
    return { status: 'pending', reference: job.reference, payoutId: job.payout_id };
  }
  async function sendPayout(userId: string, mode: 'automatic' | 'manual', actor: string, override?: unknown, reward?: any) {
    requireBusinessApproval();
    await requireStorageReady();
    const inv = reward ? {id:null,payout_phase:'referral',next_payment_date:reward.created_at.slice(0,10)}
      : await query(db().from('investments').select('*').eq('user_id', userId).eq('status','active').order('created_at', { ascending: false }).limit(1).maybeSingle());
    if (!inv || !inv.next_payment_date || inv.next_payment_date > new Date().toISOString().slice(0,10)) throw new BachsError('No investment payout is due for this investor.', 409);
    const phase = reward ? 'referral' : /^week[1-4]$/.test(inv.payout_phase) ? inv.payout_phase : 'week1';
    const amount = reward ? decimalAmount(reward.amount) : payoutAmount(inv.amount, phase === 'week4', store.platform_settings.interest_rate ?? '0.15');
    if (override !== undefined && decimalAmount(override) !== amount) throw new BachsError('The payout must match the amount due for this investment week.',400,'PAYOUT_AMOUNT_MISMATCH');
    const existing = await query(reward ? db().from('bachs_payout_jobs').select('*').eq('reward_id',reward.id).maybeSingle()
      : db().from('bachs_payout_jobs').select('*').eq('investment_id', inv.id).eq('phase', phase).eq('due_date', inv.next_payment_date).maybeSingle());
    if (existing) return existing.payout_id ? reconcileJob(existing) : { status: 'pending', reference: existing.reference, message: 'This payout has already been claimed. Reconciliation is required before another money movement.' };
    const { accountId, destination } = await payoutAccount(userId);
    const reference = `sigma-payout-${crypto.randomUUID()}`;
    const job = { reference, user_id: userId, investment_id: inv.id, reward_id:reward?.id || null, amount, phase, due_date: inv.next_payment_date,
      account_id: accountId, destination_id: destination.id, mode, actor };
    // Only the winner of the unique investment/phase/date claim may move money.
    const claim = await db().from('bachs_payout_jobs').insert(job).select().single();
    if (claim.error?.code === '23505') return { status: 'pending', message: 'This payout was claimed by another run.' };
    if (claim.error) throw new BachsError('The payout could not be safely reserved.', 503);
    try {
      // Quotes report net delivery. Confirm a second quote covers the exact requested amount and fee.
      const quote = await bachsRequest('/v1/payouts/quotes', { method:'POST', accountId, idempotencyKey:`quote:${reference}:1`, body:{from_currency:'NGN',to_currency:'NGN',amount} });
      if(decimalAmount(quote.from_amount)!==amount)throw new BachsError('Payout quote amount mismatch.',409);
      const fee = minorUnits(quote.from_amount) - minorUnits(quote.to_amount,true);
      if (fee < 0n) throw new BachsError('The payout fee could not be verified.', 409);
      const total = majorUnits(minorUnits(amount) + fee);
      const confirmed = await bachsRequest('/v1/payouts/quotes', { method:'POST', accountId, idempotencyKey:`quote:${reference}:2`, body:{from_currency:'NGN',to_currency:'NGN',amount:total} });
      if (decimalAmount(confirmed.from_amount) !== total || decimalAmount(confirmed.to_amount) !== amount) throw new BachsError('The payout quote does not deliver the requested amount.', 409);
      await query(db().from('bachs_payout_jobs').update({ total_debit:total, status:'transferring' }).eq('reference',reference));
      const transfer = await bachsRequest('/v1/transfers', { method:'POST', idempotencyKey:`transfer:${reference}`, body:{destination:accountId,amount:total,currency:'NGN',transfer_group:reference,metadata:{reference}} });
      await query(db().from('bachs_payout_jobs').update({transfer_id:transfer.id,status:'funded'}).eq('reference',reference));
      if (transfer.status !== 'paid') throw new BachsError('The funding transfer is not confirmed yet.',409);
      await query(db().from('bachs_payout_jobs').update({status:'payout_submitting'}).eq('reference',reference));
      const payout = await bachsRequest('/v1/payouts', { method:'POST', accountId, idempotencyKey:`payout:${reference}`, body:{destination:destination.id,amount,reference} });
      remember(await query(db().rpc('bachs_record_pending_payout', {p_reference:reference,p_payout_id:payout.id})));
      return reconcileJob({ ...job, payout_id:payout.id });
    } catch (error) {
      await query(db().from('bachs_payout_jobs').update({error:error instanceof Error ? error.message : 'Unknown outcome'}).eq('reference',reference));
      throw error;
    }
  }
  async function reconcilePending() {
    const jobs = await query(db().from('bachs_payout_jobs').select('*').not('status','in','(successful,failed)').limit(100));
    for (const job of jobs || []) {
      if (!job.payout_id && job.transfer_id) {
        // An interrupted write is recovered by reading its reference, never by creating a second payout.
        const remote = await bachsRequest('/v1/payouts?limit=100', { accountId:job.account_id });
        const found = remote.items?.find((p:any) => p.reference === job.reference);
        if (found) {
          job.payout_id = found.id;
          remember(await query(db().rpc('bachs_record_pending_payout',{p_reference:job.reference,p_payout_id:found.id})));
        }
      }
      if (job.payout_id) await reconcileJob(job);
    }
  }

  app.get('/api/config', (_req,res) => res.json({ paymentProvider:'bachs', bachsConfigured:isBachsConfigured() && (bachsApiKey().startsWith('sk_sandbox_') || process.env.BACHS_BUSINESS_APPROVED==='1'),
    bachsSandbox:bachsApiKey().startsWith('sk_sandbox_'), bachsWebhookConfigured:Boolean(bachsWebhookSecret()),
    isSupabaseLive:Boolean(database), minDepositNgn:FUNDING_PLAN_AMOUNTS[0], fundingPlanAmounts:FUNDING_PLAN_AMOUNTS, referralRate:0.05, bachsWebhookUrl:bachsWebhookUrl(),
    payoutHint:'Bachs Connect verification and an approved NGN payout destination are required.' }));
  app.get('/api/banks', endpoint(async (_req,res) => {
    const result = await bachsRequest('/v1/reference/banks?country=NG');
    res.json({data:(result.banks || []).map((b:any,i:number)=>({...b,id:b.code || i}))});
  }));
  app.post('/api/verify-account', endpoint(async (req,res) => {
    await identity(req);
    const {account_number,account_bank} = req.body;
    if (!/^\d{10}$/.test(String(account_number)) || !account_bank) throw new BachsError('A 10-digit account number and bank code are required.',400);
    const result = await bachsRequest('/v1/misc/bank-accounts/resolve', { method:'POST',idempotencyKey:crypto.randomUUID(),body:{account_number,bank_code:account_bank,country:'NG'} });
    if (!result.resolved || !result.account_name) throw new BachsError('Bachs could not verify this account.',400);
    res.json({data:result});
  }));
  function checkoutAddress(session: any): string {
    let address: URL;
    try { address=new URL(session.checkout_url); } catch { throw new BachsError('Bachs did not return a usable checkout.',502); }
    if(address.protocol!=='https:' || address.username || address.password || address.port || !['checkout.bachs.io','sandbox-checkout.bachs.io'].includes(address.hostname))throw new BachsError('Bachs returned an unexpected checkout address.',502);
    return address.href;
  }
  async function resumeCheckout(request: any, amount: string, monthlyAmount: string | null) {
    const enrolledAmount=request.monthly_amount==null?null:decimalAmount(request.monthly_amount);
    const expectedAmount=request.setup_only?enrolledAmount:decimalAmount(request.amount);
    if(expectedAmount!==amount || enrolledAmount!==monthlyAmount)throw new BachsError('This payment attempt belongs to a different funding plan.',409,'IDEMPOTENCY_CONFLICT');
    if(request.credited)throw new BachsError('This payment is already credited. Refresh your dashboard before starting another contribution.',409,'ALREADY_CREDITED');
    if(!request.checkout_id)throw new BachsError('This payment attempt is still being reconciled. Use Sync or contact support; do not start another payment.',503,'RECONCILIATION_REQUIRED');
    const session=await bachsRequest('/v1/checkout-sessions/'+encodeURIComponent(request.checkout_id));
    if(session.reference!==request.reference || session.checkout_id!==request.checkout_id)throw new BachsError('Checkout reference mismatch.',409);
    if(session.status==='completed')return {...await settleCheckout(request),completed:true,reference:request.reference,chargeId:request.checkout_id,sessionId:request.checkout_id,redirectUrl:null};
    if(session.status!=='open')throw new BachsError('This checkout has expired or was cancelled. Start a new payment attempt.',409,'CHECKOUT_EXPIRED');
    return {success:true,completed:false,status:'pending',chargeId:request.checkout_id,sessionId:request.checkout_id,reference:request.reference,redirectUrl:checkoutAddress(session),amountCharged:Number(request.amount),monthlyPlanAmount:enrolledAmount?Number(enrolledAmount):null,setupOnly:request.setup_only};
  }
  app.post('/api/bachs/initiate', endpoint(async (req,res) => {
    const user = await identity(req);
    const amount = decimalAmount(req.body.amount);
    const plan = getFundingPlan(amount);
    if (!plan) throw new BachsError(FUNDING_PLAN_ERROR,400,'INVALID_FUNDING_PLAN');
    if (req.body.currency && String(req.body.currency).toUpperCase() !== 'NGN') throw new BachsError('Funding plans use NGN.',400);
    const recurring = req.body.isRecurringPlan === true;
    const monthlyAmount = recurring ? decimalAmount(req.body.monthlyPlanAmount || req.body.amount) : null;
    if (monthlyAmount && monthlyAmount !== amount) throw new BachsError('The monthly amount must match the selected funding plan.',400,'INVALID_FUNDING_PLAN');
    const key=req.body.idempotencyKey || req.get('Idempotency-Key');
    if(typeof key!=='string' || !/^[a-zA-Z0-9_-]{16,100}$/.test(key))throw new BachsError('A valid payment attempt key is required. Refresh the page and try again.',400,'IDEMPOTENCY_KEY_REQUIRED');
    const reference='sigma-'+crypto.createHash('sha256').update(user.id+':'+key).digest('hex');
    const previous=await requestFor(reference);
    if(previous)return res.json(await resumeCheckout(previous,amount,monthlyAmount));
    requireBusinessApproval();
    const profile = await profileFor(user);
    await requireStorageReady();
    await requireExactCheckoutFees();
    const customer = await customerFor(user, profile.name || 'Investor');
    const setupOnly = recurring && Number(profile.total_invested)>0;
    const chargeAmount = setupOnly ? '0.00' : amount;
    const request = { reference,user_id:user.id,kind:'checkout',amount:chargeAmount,currency:'NGN',phase:String(req.body.phase || 'Active Plan'),monthly_amount:monthlyAmount,setup_only:setupOnly };
    const claim=await db().from('bachs_requests').insert(request);
    if(claim.error?.code==='23505')return res.json(await resumeCheckout(await requestFor(reference),amount,monthlyAmount));
    await query(Promise.resolve(claim));
    const session = await bachsRequest('/v1/checkout-sessions', { method:'POST',idempotencyKey:reference,body:{
      ...(setupOnly?{}:{pricing:{amount:chargeAmount,currency:'NGN'}}), customer:{customer_id:customer.customer_id},
      reference,metadata:{userId:user.id,reference,fundingPlan:plan.id},save_payment_method:recurring,
      ...(recurring?{payment_method_types:['NGN_CARD']}:{}),
      success_url:`${frontendUrl()}/dashboard?bachs_return=1&reference=${encodeURIComponent(reference)}`,
      cancel_url:`${frontendUrl()}/dashboard?bachs_cancel=1`,
    } });
    const checkoutId = session.checkout_id;
    if (!checkoutId || !session.checkout_url) throw new BachsError('Bachs did not return a usable checkout.',502);
    const redirectUrl = checkoutAddress(session);
    await query(db().from('bachs_requests').update({checkout_id:checkoutId}).eq('reference',reference));
    res.json({success:true,completed:false,status:'pending',chargeId:checkoutId,sessionId:checkoutId,reference,
      redirectUrl,amountCharged:Number(chargeAmount),monthlyPlanAmount:monthlyAmount?Number(monthlyAmount):null,setupOnly});
  }));
  app.post('/api/bachs/verify', endpoint(async (req,res) => {
    const user = await identity(req);
    const request = await requestFor(req.body.txRef || req.body.reference,req.body.checkoutId || req.body.sessionId || req.body.chargeId);
    if (!request || request.user_id!==user.id) throw new BachsError('Payment request not found.',404);
    const result = await settleCheckout(request,req.body.checkoutId || req.body.sessionId || req.body.chargeId);
    res.status(result.success?200:202).json(result);
  }));
  app.post('/api/bachs/sync', endpoint(async (req,res) => {
    const user = await identity(req, req.body.all === true);
    let requests = db().from('bachs_requests').select('*').eq('credited',false).eq('kind','checkout').not('checkout_id','is',null).limit(100);
    if (req.body.all !== true) requests = requests.eq('user_id', user.id);
    const pending = await query(requests);
    let syncedCount = 0;
    for (const request of pending || []) if ((await settleCheckout(request)).success) syncedCount++;
    await refreshCard(user.id);
    res.json({success:true,syncedCount,totalPayments:store.payments.filter(p=>p.user_id===user.id).length});
  }));
  app.post('/api/investor/connect/onboard', endpoint(async (req,res) => {
    const user = await identity(req); const profile = await profileFor(user);
    // NGN investment payouts stay NGN: never guess an FX rate for an investor's returns.
    if (String(req.body.country || 'NG').toUpperCase()!=='NG') throw new BachsError('This NGN investment account currently pays out to Nigerian bank accounts.',400);
    const me = await bachsRequest('/v1/accounts/me');
    if (!await isPlatformConnectReady(me)) throw new BachsError('Bachs Connect is not active on the platform account. Request it in the Bachs dashboard and complete the required verification.',409,'CONNECT_NOT_ACTIVE');
    let bank = await query(db().from('bank_details').select('*').eq('user_id',user.id).maybeSingle());
    let accountId = bank?.bachs_account_id;
    if (!accountId) {
      const account = await bachsRequest('/v1/accounts', {method:'POST',idempotencyKey:`recipient:${user.id}`,body:{contact_email:user.email,display_name:profile.name || user.email,country:'NG',entity_type:'individual',configuration:{recipient:{capabilities:{payouts:{requested:true},transfers:{requested:true}}}}}});
      accountId=account.id;
      bank=await query(db().from('bank_details').upsert({user_id:user.id,account_name:profile.name || 'Investor',country:'NG',currency:'NGN',bachs_account_id:accountId}).select().single());
      store.bank_details.set(user.id,bank);
    }
    const link=await bachsRequest(`/v1/accounts/${encodeURIComponent(accountId)}/account-links`,{method:'POST',idempotencyKey:crypto.randomUUID(),body:{type:'onboarding',return_url:`${frontendUrl()}/dashboard?connect_return=1`,refresh_url:`${frontendUrl()}/dashboard?connect_refresh=1`}});
    if (new URL(link.url).protocol !== 'https:') throw new BachsError('Bachs returned an insecure onboarding address.',502);
    res.json({success:true,onboardingUrl:link.url,bachsAccountId:accountId});
  }));
  app.get('/api/investor/connect/status/:userId', endpoint(async (req,res) => {
    const user=await identity(req);
    if(user.id!==req.params.userId) throw new BachsError('Access denied.',403);
    try { const result=await payoutAccount(user.id); res.json(result.bank); }
    catch(error) { if(error instanceof BachsError && error.status===409) res.json({...(store.bank_details.get(user.id)||{}),payouts_enabled:false,message:error.message}); else throw error; }
  }));
  app.post('/api/investor/bank-details', endpoint(async (req,res) => {
    const user=await identity(req);
    const bank=await query(db().from('bank_details').select('*').eq('user_id',user.id).maybeSingle());
    if(!bank?.bachs_account_id) throw new BachsError('Complete Bachs bank onboarding first.',409);
    const body=req.body;
    if(!/^\d{10}$/.test(String(body.accountNumber)) || !body.bankCode) throw new BachsError('A Nigerian bank and 10-digit account number are required.',400);
    const destination=await bachsRequest('/v1/payouts/destinations',{method:'POST',accountId:bank.bachs_account_id,idempotencyKey:crypto.randomUUID(),body:{type:'bank_account',currency:'NGN',account_number:body.accountNumber,bank_code:body.bankCode,name:'Investor bank'}});
    await bachsRequest(`/v1/payouts/destinations/${encodeURIComponent(destination.id)}`,{method:'PATCH',accountId:bank.bachs_account_id,idempotencyKey:crypto.randomUUID(),body:{is_default:true}});
    const updated=await query(db().from('bank_details').update({bachs_destination_id:destination.id,account_number:destination.account_number,bank_code:destination.bank_code,bank_name:destination.bank_name,account_name:destination.account_name || bank.account_name,payouts_enabled:false,connect_onboarding_complete:false}).eq('user_id',user.id).select().single());
    store.bank_details.set(user.id,updated); res.json(updated);
  }));
  app.post('/api/investor/auto-debit-plan', endpoint(async (req,res) => {
    const user=await identity(req); const amount=decimalAmount(req.body.amount);
    if(!isFundingPlanAmount(amount)) throw new BachsError(FUNDING_PLAN_ERROR,400,'INVALID_FUNDING_PLAN');
    const customer=await query(db().from('bachs_customers').select('*').eq('user_id',user.id).maybeSingle());
    if(!customer?.payment_method_id) throw new BachsError('Enroll your card with Bachs first. Cards saved with previous providers cannot be reused.',409);
    await query(db().from('bachs_customers').update({monthly_amount:amount,active:true,next_charge_date:customer.next_charge_date || new Date(new Date().setMonth(new Date().getMonth()+1)).toISOString().slice(0,10)}).eq('user_id',user.id));
    await refreshCard(user.id); res.json(store.auto_debit_plans.get(user.id));
  }));
  app.post('/api/investor/cancel-subscription', endpoint(async (req,res) => {
    const user=await identity(req);
    await query(db().from('bachs_customers').update({active:false}).eq('user_id',user.id));
    await query(db().from('profiles').update({payment_plan_id:null}).eq('id',user.id));
    await refreshCard(user.id); res.json({success:true,message:'Future Bachs auto-debits have been cancelled.'});
  }));
  app.post('/api/investor/auto-debit-reminders', endpoint(async (req,res) => {
    const user=await runner(req); await requireAutomationReady(user); requireBusinessApproval(); await requireStorageReady();
    const tomorrow=new Date(Date.now()+86400000).toISOString().slice(0,10);
    const customers=await query(db().from('bachs_customers').select('*').eq('active',true).eq('next_charge_date',tomorrow));
    let sent=0;
    for(const customer of customers || []) {
      if(!customer.payment_method_id || !isFundingPlanAmount(customer.monthly_amount)) continue;
      const h=crypto.createHash('sha256').update('bachs-reminder:'+customer.user_id+':'+tomorrow).digest('hex');
      const id=[h.slice(0,8),h.slice(8,12),h.slice(12,16),h.slice(16,20),h.slice(20,32)].join('-');
      const notification={id,title:'Auto-debit tomorrow',body:'Your ₦'+Number(customer.monthly_amount).toLocaleString('en-NG')+' funding plan is scheduled for tomorrow ('+tomorrow+'). You can cancel it in your dashboard.',audience:'single',target_user_id:customer.user_id,icon:'calendar',image_url:null,sent_at:new Date().toISOString(),delivery_status:'delivered'};
      const result=await db().from('notifications').insert(notification);
      if(result.error?.code==='23505')continue;
      await query(Promise.resolve(result));store.notifications?.unshift(notification);sent++;
    }
    res.json({success:true,sent});
  }));
  app.post('/api/investor/process-auto-debits', endpoint(async (req,res) => {
    const user=await runner(req); await requireAutomationReady(user); requireBusinessApproval();
    await requireStorageReady(); await requireExactCheckoutFees();
    const today=new Date().toISOString().slice(0,10); const results:any[]=[];
    const customers=await query(db().from('bachs_customers').select('*').eq('active',true).lte('next_charge_date',today));
    for(const customer of customers || []) {
      if(!isFundingPlanAmount(customer.monthly_amount)) {results.push({userId:customer.user_id,status:'blocked',message:'Select a current funding plan before resuming automatic debits.'});continue;}
      const profile=await query(db().from('profiles').select('*').eq('id',customer.user_id).single());
      const reference=`sigma-debit-${customer.user_id}-${customer.next_charge_date}`;
      const claim=await db().from('bachs_requests').insert({reference,user_id:customer.user_id,kind:'auto_debit',amount:customer.monthly_amount,phase:profile.current_phase || 'Active Plan',monthly_amount:customer.monthly_amount}).select().single();
      if(claim.error?.code==='23505') {results.push({userId:customer.user_id,status:'pending',reference});continue;}
      if(claim.error) throw new BachsError('Auto-debit storage is unavailable.',503);
      const payment=await bachsRequest('/v1/charges',{method:'POST',idempotencyKey:reference,body:{customer:customer.customer_id,payment_method:customer.payment_method_id,amount:decimalAmount(customer.monthly_amount),currency:'NGN',reference,metadata:{userId:customer.user_id,reference}}});
      await query(db().from('bachs_requests').update({payment_id:payment.payment_id,status:payment.status}).eq('reference',reference));
      // Collection webhooks, never a 201 response, credit an auto-debit and advance its date.
      results.push({userId:customer.user_id,status:payment.status,reference});
    }
    res.json({success:true,processed:results.length,results});
  }));
  app.post('/api/admin/payout-mode', endpoint(async (req,res) => {
    const user=await identity(req,true); const mode=req.body.mode;
    if(!['automatic','manual'].includes(mode)) throw new BachsError('Invalid payout mode.',400);
    await query(db().from('platform_settings').upsert({key:'payout_mode',value:{mode,updated_by:user.email}}));
    store.platform_settings.payout_mode=mode; res.json({success:true,mode});
  }));
  app.post('/api/admin/payouts/manual-pay', endpoint(async (req,res) => {
    const user=await identity(req,true); if(!req.body.userId || !req.body.referenceNote) throw new BachsError('Investor and reference note required.',400);
    const result=await sendPayout(req.body.userId,'manual',user.email,req.body.amount!==undefined && req.body.amount!==null?decimalAmount(req.body.amount):undefined);
    res.json(result.payout || {user_id:req.body.userId,amount:req.body.amount,status:'pending',notes:'Bachs payout awaiting confirmation'});
  }));
  app.post('/api/admin/payouts/manual-batch', endpoint(async (req,res) => {
    const user=await identity(req,true); if(!req.body.referenceNote) throw new BachsError('Reference note required.',400);
    const ids=req.body.payAllDue?((await query(db().from('investments').select('user_id').eq('status','active').lte('next_payment_date',new Date().toISOString().slice(0,10)))) || []).map((i:any)=>i.user_id):req.body.userIds;
    if(!Array.isArray(ids)) throw new BachsError('Select investors to pay.',400);
    const results:any[]=[];
    for(const id of new Set<string>(ids)) {try{const result=await sendPayout(id,'manual',user.email);results.push({userId:id,status:result.payout?.status || result.status || 'pending'});}catch(error){results.push({userId:id,status:'failed',message:error instanceof Error?error.message:'Payout failed'});}}
    res.json({success:true,paid:results.filter(r=>r.status==='successful').length,pending:results.filter(r=>r.status==='pending').length,failed:results.filter(r=>r.status==='failed').length,skipped:0,results});
  }));
  app.post('/api/payouts/run-cron', endpoint(async (req,res) => {
    const user=await runner(req); await requireAutomationReady(user); await reconcilePending();
    const setting=await query(db().from('platform_settings').select('value').eq('key','payout_mode').maybeSingle());
    const mode=setting?.value?.mode || 'manual'; store.platform_settings.payout_mode=mode;
    const investments=await query(db().from('investments').select('*').eq('status','active').lte('next_payment_date',new Date().toISOString().slice(0,10)));
    const logs:string[]=[];let successfulTransfers=0;let failedTransfers=0;let pendingTransfers=0;
    if(mode==='automatic') for(const inv of investments || []) {try{const result=await sendPayout(inv.user_id,'automatic',user.email);if(result.payout?.status==='successful') successfulTransfers++;else pendingTransfers++;}catch(error){failedTransfers++;logs.push(error instanceof Error?error.message:'Payout failed');}}
    let referralPaid=0;
    if(mode==='automatic' && new Date().getUTCDay()===0) {
      const rewards=await query(db().from('bachs_referral_rewards').select('*').eq('status','pending').limit(100));
      for(const reward of rewards || []) {try{const result=await sendPayout(reward.referrer_id,'automatic',user.email,undefined,reward);if(result.payout?.status==='successful')referralPaid++;}catch(error){failedTransfers++;logs.push(error instanceof Error?error.message:'Referral payout failed');}}
    }
    res.json({runTimestamp:new Date().toISOString(),payoutMode:mode,totalChecked:investments?.length || 0,eligibleCount:investments?.length || 0,successfulTransfers,failedTransfers,pendingTransfers,referralPaid,queuedForManual:mode==='manual'?investments?.length || 0:0,logs});
  }));
  app.get('/api/bachs/settlement-schedule', endpoint(async (req,res) => {await identity(req,true);res.json(await bachsRequest('/v1/balance_settings'));}));
  app.post('/api/bachs/settlement-schedule', endpoint(async (req,res) => {
    await identity(req,true);
    const interval=req.body.interval;
    if(!['manual','instant','daily','weekly','monthly'].includes(interval)) throw new BachsError('Invalid settlement interval.',400);
    const schedule:any={interval,payout_currency:'NGN',minimum_amount:decimalAmount(req.body.minimumAmount || '0',true)};
    if(['daily','weekly','monthly'].includes(interval)) {const hour=Number(req.body.hourUtc ?? 9);if(!Number.isInteger(hour)||hour<0||hour>23) throw new BachsError('UTC hour must be 0–23.',400);schedule.anchor_hour_utc=hour;}
    if(interval==='weekly') schedule.weekly_payout_days=req.body.weeklyDays || ['monday'];
    if(interval==='monthly') schedule.monthly_payout_days=req.body.monthlyDays || [1];
    const destinations=await bachsRequest('/v1/payouts/destinations?limit=100');
    if(interval!=='manual' && !destinations.items?.some((d:any)=>d.is_default && d.is_usable && d.currency==='NGN')) throw new BachsError('An approved default company NGN destination is required.',409);
    res.json(await bachsRequest('/v1/balance_settings',{method:'POST',idempotencyKey:crypto.randomUUID(),body:{schedule_by_currency:{NGN:schedule}}}));
  }));
  app.get('/api/bachs/readiness', endpoint(async (req,res) => {
    await runner(req); const account=await bachsRequest('/v1/accounts/me');
    await requireStorageReady();
    const connectActive=await isPlatformConnectReady(account);
    res.json({configured:true,sandbox:bachsApiKey().startsWith('sk_sandbox_'),webhookConfigured:Boolean(bachsWebhookSecret()),databaseReady:true,
      businessApproved:process.env.BACHS_BUSINESS_APPROVED==='1',automationEnabled:process.env.BACHS_AUTOMATION_ENABLED==='1',connectActive:Boolean(connectActive),capabilities:account.enabled_capabilities,webhookUrl:bachsWebhookUrl()});
  }));
  app.get('/api/bachs/payout-jobs', endpoint(async (req,res) => {
    await identity(req,true);
    const jobs = await query(db().from('bachs_payout_jobs').select('reference,user_id,amount,phase,status,transfer_id,payout_id,error,created_at').order('created_at',{ascending:false}).limit(100));
    res.json({jobs});
  }));
  app.post('/api/bachs/payout-jobs/:reference/reconcile', endpoint(async (req,res) => {
    await identity(req,true);
    await reconcilePending();
    const job = await query(db().from('bachs_payout_jobs').select('*').eq('reference',req.params.reference).maybeSingle());
    if (!job) throw new BachsError('Payout job not found.',404);
    // This endpoint only looks up existing movements and records confirmed outcomes.
    res.json(job.payout_id ? await reconcileJob(job) : {status:job.status,reference:job.reference,message:'No payout ID is confirmed. Inspect Bachs transfers and logs for this reference before resubmitting any money movement.'});
  }));
  app.post('/api/bachs/webhook', endpoint(async (req,res) => {
    const raw=(req as any).rawBody;
    if(!bachsWebhookSecret()) throw new BachsError('Webhook signing secret is not configured.',503);
    if(!Buffer.isBuffer(raw) || !verifyBachsSignature(raw,{timestamp:req.get('X-Bachs-Timestamp'),signature:req.get('X-Bachs-Signature'),signatureV2:req.get('X-Bachs-Signature-V2')})) throw new BachsError('Invalid Bachs webhook signature.',401);
    let event:any;try{event=JSON.parse(raw.toString('utf8'));}catch{throw new BachsError('Invalid webhook JSON.',400);}
    if(!event.id || !event.type || !event.data) throw new BachsError('Invalid webhook event.',400);
    const seen=await query(db().from('bachs_webhook_events').select('id').eq('id',event.id).maybeSingle());
    if(seen) return res.json({received:true,duplicate:true});
    const data=event.data;
    if(event.type==='checkout.completed' || event.type==='collection.succeeded') {
      const reference=data.reference || data.metadata?.reference;
      const request=(reference || data.checkout_id)?await requestFor(reference,data.checkout_id):null;
      if(request) {
        if(request.kind==='checkout') {
          const result=await settleCheckout(request,data.checkout_id);
          if(!result.success)throw new BachsError('Payment confirmation is not available yet. Retry this event.',503,'SETTLEMENT_PENDING');
        }
        else {
          const payment=await bachsRequest(`/v1/payments/${encodeURIComponent(request.payment_id || data.payment_id || data.charge_id)}`);
          const fee=payment.merchant_bears_cost===false?minorUnits(payment.fees?.amount || '0',true):0n;
          if(payment.reference!==request.reference || payment.status!=='succeeded' || payment.currency!=='NGN' || minorUnits(payment.amount)-fee!==minorUnits(request.amount)) throw new BachsError('Auto-debit settlement mismatch.',409);
          remember(await query(db().rpc('bachs_credit_payment',{p_reference:request.reference,p_payment_id:payment.payment_id})));
          await refreshCard(request.user_id);
        }
      }
    } else if(event.type==='payment_method.saved') {
      const customerId=data.customer?.customer_id;
      if(customerId && data.payment_method_id) {
        const card={card_brand:data.card_brand,card_last4:data.card_last4,card_exp_month:String(data.card_exp_month),card_exp_year:String(data.card_exp_year),currency:data.currency};
        const customer=await query(db().from('bachs_customers').update({payment_method_id:data.payment_method_id,card_details:card}).eq('customer_id',customerId).select().maybeSingle());
        if(customer) await refreshCard(customer.user_id);
      }
    } else if(event.type==='payout.paid' || event.type==='payout.failed') {
      const job=await query(db().from('bachs_payout_jobs').select('*').eq('reference',data.reference || '').maybeSingle());
      if(job) {
        if(event.account!==job.account_id && event.organization_id!==job.account_id) throw new BachsError('Payout account mismatch.',409);
        if(!job.payout_id) {const id=data.withdrawal_id || data.payout_id || data.id; if(id){job.payout_id=id;remember(await query(db().rpc('bachs_record_pending_payout',{p_reference:job.reference,p_payout_id:id})));}}
        await reconcileJob(job);
      }
    }
    const stored=await db().from('bachs_webhook_events').insert({id:event.id,type:event.type});
    if(stored.error && stored.error.code!=='23505') throw new BachsError('Webhook could not be recorded. Please retry.',503);
    res.json({received:true});
  }));
  // Refresh new-provider card/plan state before the existing dashboard read handler.
  app.post('/api/investor/register-profile', endpoint(async (req,res) => {
    const user=await identity(req);
    if(req.body.id && req.body.id!==user.id) throw new BachsError('Access denied.',403);
    const profile=await profileFor({...user,metadata:{...user.metadata,referral_code:user.metadata.referral_code || req.body.referralCode}});
    const updated=await query(db().from('profiles').update({name:req.body.name || profile.name,phone:req.body.phone || profile.phone}).eq('id',user.id).select().single());
    store.profiles.set(user.id,updated);res.json(updated);
  }));
  app.get('/api/investor/dashboard/:id', endpoint(async (req,_res,next) => {
    const user = await identity(req);
    if (user.id !== req.params.id) throw new BachsError('Access denied.', 403);
    await refreshCard(user.id);
    await profileFor(user);
    const referrals=await query(db().from('profiles').select('id,name,email,referral_initial_credited').eq('referred_by',user.id));
    const rewards=await query(db().from('bachs_referral_rewards').select('referred_id,amount,created_at').eq('referrer_id',user.id));
    store.referrals=store.referrals.filter((r:any)=>r.referrer_id!==user.id);
    for(const referral of referrals || []) {
      const reward=rewards?.find((r:any)=>r.referred_id===referral.id);
      store.referrals.push({id:referral.id,referrer_id:user.id,referred_id:referral.id,referred_name:referral.name,referred_email:referral.email,earned_total:Number(reward?.amount || 0),created_at:reward?.created_at});
    }
    const bank = await query(db().from('bank_details').select('*').eq('user_id', user.id).maybeSingle());
    if (bank?.bachs_account_id) {
      try { await payoutAccount(user.id); }
      catch (error) { if (!(error instanceof BachsError && error.status === 409)) throw error; }
    }
    next();
  }));
}
