-- Apply once in Supabase SQL Editor BEFORE deploying the Bachs API.
-- Existing provider columns and historical transactions are retained.
-- Preserve the existing 5% first-investment referral reward and Sunday payout rule.
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS referral_code text;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS referred_by uuid REFERENCES public.profiles(id);
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS referral_earnings numeric(15,2) DEFAULT 0;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS referral_pending_payout numeric(15,2) DEFAULT 0;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS referral_paid_total numeric(15,2) DEFAULT 0;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS referral_initial_credited boolean DEFAULT false;
ALTER TABLE public.bank_details ADD COLUMN IF NOT EXISTS bachs_account_id text;
ALTER TABLE public.bank_details ADD COLUMN IF NOT EXISTS bachs_destination_id text;
ALTER TABLE public.bank_details ADD COLUMN IF NOT EXISTS country text DEFAULT 'NG';
ALTER TABLE public.bank_details ADD COLUMN IF NOT EXISTS currency text DEFAULT 'NGN';
ALTER TABLE public.bank_details ADD COLUMN IF NOT EXISTS connect_onboarding_complete boolean DEFAULT false;
ALTER TABLE public.bank_details ADD COLUMN IF NOT EXISTS payouts_enabled boolean DEFAULT false;
ALTER TABLE public.bank_details ALTER COLUMN account_number DROP NOT NULL;
ALTER TABLE public.bank_details ALTER COLUMN bank_code DROP NOT NULL;
ALTER TABLE public.bank_details ALTER COLUMN bank_name DROP NOT NULL;
ALTER TABLE public.payments ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE public.payments ADD COLUMN IF NOT EXISTS provider_reference text;
ALTER TABLE public.payments ADD COLUMN IF NOT EXISTS bachs_payment_id text;
ALTER TABLE public.payments ADD COLUMN IF NOT EXISTS bachs_checkout_id text;
ALTER TABLE public.payments ADD COLUMN IF NOT EXISTS currency text DEFAULT 'NGN';
CREATE UNIQUE INDEX IF NOT EXISTS payments_bachs_payment ON public.payments (bachs_payment_id) WHERE bachs_payment_id IS NOT NULL;
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS provider_transfer_id text;
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS currency text DEFAULT 'NGN';
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS payout_phase text;
CREATE UNIQUE INDEX IF NOT EXISTS payouts_bachs_transfer ON public.payouts (provider_transfer_id) WHERE provider = 'bachs' AND provider_transfer_id IS NOT NULL;
ALTER TABLE public.investments ADD COLUMN IF NOT EXISTS currency text DEFAULT 'NGN';
ALTER TABLE public.investments ADD COLUMN IF NOT EXISTS cycle_start_date timestamptz;
ALTER TABLE public.investments ADD COLUMN IF NOT EXISTS payout_phase text DEFAULT 'week1';
UPDATE public.investments SET cycle_start_date = start_date WHERE cycle_start_date IS NULL;

CREATE TABLE IF NOT EXISTS public.bachs_customers (
  user_id uuid PRIMARY KEY REFERENCES public.profiles(id),
  customer_id text NOT NULL UNIQUE,
  payment_method_id text,
  card_details jsonb,
  monthly_amount numeric(15,2),
  next_charge_date date,
  active boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS public.bachs_requests (
  reference text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.profiles(id),
  kind text NOT NULL CHECK (kind IN ('checkout', 'auto_debit')),
  amount numeric(15,2) NOT NULL CHECK (amount >= 0),
  currency text NOT NULL DEFAULT 'NGN' CHECK (currency = 'NGN'),
  phase text NOT NULL,
  monthly_amount numeric(15,2),
  setup_only boolean NOT NULL DEFAULT false,
  checkout_id text UNIQUE,
  payment_id text UNIQUE,
  status text NOT NULL DEFAULT 'pending',
  credited boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.bachs_referral_rewards (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  referrer_id uuid NOT NULL REFERENCES public.profiles(id),
  referred_id uuid NOT NULL UNIQUE REFERENCES public.profiles(id),
  payment_id text NOT NULL UNIQUE,
  amount numeric(15,2) NOT NULL CHECK (amount > 0),
  status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.bachs_payout_jobs (
  reference text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.profiles(id),
  investment_id uuid REFERENCES public.investments(id),
  reward_id uuid UNIQUE REFERENCES public.bachs_referral_rewards(id),
  amount numeric(15,2) NOT NULL CHECK (amount > 0),
  phase text NOT NULL,
  due_date date NOT NULL,
  account_id text NOT NULL,
  destination_id text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('automatic','manual')),
  actor text NOT NULL,
  status text NOT NULL DEFAULT 'claimed',
  transfer_id text,
  payout_id text UNIQUE,
  total_debit numeric(15,2),
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (investment_id, phase, due_date)
);
ALTER TABLE public.bachs_payout_jobs ALTER COLUMN investment_id DROP NOT NULL;
ALTER TABLE public.bachs_payout_jobs ADD COLUMN IF NOT EXISTS reward_id uuid UNIQUE REFERENCES public.bachs_referral_rewards(id);
CREATE TABLE IF NOT EXISTS public.bachs_webhook_events (
  id text PRIMARY KEY,
  type text NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.bachs_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bachs_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bachs_payout_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bachs_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bachs_referral_rewards ENABLE ROW LEVEL SECURITY;
-- No client write policy: all financial writes use the server's service role.
REVOKE ALL ON public.bachs_customers, public.bachs_requests, public.bachs_payout_jobs, public.bachs_webhook_events FROM anon, authenticated;
GRANT ALL ON public.bachs_customers, public.bachs_requests, public.bachs_payout_jobs, public.bachs_webhook_events TO service_role;
REVOKE ALL ON public.bachs_referral_rewards FROM anon, authenticated;
GRANT ALL ON public.bachs_referral_rewards TO service_role;

CREATE OR REPLACE FUNCTION public.bachs_credit_payment(p_reference text, p_payment_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE r bachs_requests; prof profiles; inv investments; pay payments; new_credit boolean := false; reward numeric(15,2);
BEGIN
  SELECT * INTO r FROM bachs_requests WHERE reference = p_reference FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown Bachs payment request'; END IF;
  SELECT * INTO prof FROM profiles WHERE id = r.user_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Investor profile missing'; END IF;
  SELECT * INTO inv FROM investments WHERE user_id = r.user_id ORDER BY created_at DESC LIMIT 1 FOR UPDATE;
  IF NOT r.credited THEN
    IF NOT r.setup_only THEN
      IF p_payment_id IS NULL OR p_payment_id = '' THEN RAISE EXCEPTION 'Payment ID required'; END IF;
      INSERT INTO payments (user_id, amount, currency, method, provider, provider_reference, bachs_payment_id, bachs_checkout_id, status, notes)
      VALUES (r.user_id, r.amount, r.currency, CASE WHEN r.monthly_amount IS NOT NULL THEN 'auto_debit' ELSE 'card' END,
        'bachs', r.reference, p_payment_id, r.checkout_id, 'successful', 'Bachs payment (' || r.phase || ')')
      RETURNING * INTO pay;
      UPDATE profiles SET total_invested = coalesce(total_invested,0) + r.amount, current_phase = r.phase, updated_at = now()
        WHERE id = r.user_id RETURNING * INTO prof;
      IF inv.id IS NULL THEN
        INSERT INTO investments (user_id, amount, phase, currency, type, status, next_payment_date, cycle_start_date, payout_phase, cycle_count)
        VALUES (r.user_id, r.amount, r.phase, 'NGN', CASE WHEN r.monthly_amount IS NULL THEN 'one-time' ELSE 'auto' END,
          'active', current_date + 7, now(), 'week1', 1) RETURNING * INTO inv;
      ELSE
        UPDATE investments SET amount = amount + r.amount, phase = r.phase, status = 'active',
          type = CASE WHEN r.monthly_amount IS NULL THEN type ELSE 'auto' END
          WHERE id = inv.id RETURNING * INTO inv;
      END IF;
      new_credit := true;
      IF prof.referred_by IS NOT NULL AND prof.referred_by <> prof.id AND NOT coalesce(prof.referral_initial_credited,false) THEN
        reward := round(r.amount * 0.05,2);
        INSERT INTO bachs_referral_rewards(referrer_id,referred_id,payment_id,amount)
          VALUES(prof.referred_by,prof.id,p_payment_id,reward);
        UPDATE profiles SET referral_earnings = coalesce(referral_earnings,0) + reward,
          referral_pending_payout = coalesce(referral_pending_payout,0) + reward WHERE id = prof.referred_by;
        UPDATE profiles SET referral_initial_credited = true WHERE id = prof.id RETURNING * INTO prof;
      END IF;
    END IF;
    UPDATE bachs_requests SET credited = true, status = 'successful', payment_id = nullif(p_payment_id,'') WHERE reference = p_reference;
    IF r.monthly_amount IS NOT NULL THEN
      UPDATE bachs_customers SET monthly_amount = r.monthly_amount, active = true,
        next_charge_date = (current_date + interval '1 month')::date WHERE user_id = r.user_id;
      UPDATE profiles SET payment_plan_id = 'bachs:' || r.user_id::text WHERE id = r.user_id RETURNING * INTO prof;
    END IF;
  ELSE
    SELECT * INTO pay FROM payments WHERE provider_reference = r.reference AND provider = 'bachs';
  END IF;
  RETURN jsonb_build_object('profile', to_jsonb(prof), 'investment', to_jsonb(inv), 'payment', to_jsonb(pay), 'newCredit', new_credit);
END $$;

CREATE OR REPLACE FUNCTION public.bachs_finish_payout(p_reference text, p_status text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE j bachs_payout_jobs; inv investments; po payouts; week_number integer;
BEGIN
  IF p_status NOT IN ('successful','failed') THEN RAISE EXCEPTION 'Invalid payout status'; END IF;
  SELECT * INTO j FROM bachs_payout_jobs WHERE reference = p_reference FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown payout'; END IF;
  SELECT * INTO inv FROM investments WHERE id = j.investment_id FOR UPDATE;
  IF j.status IN ('successful','failed') THEN
    SELECT * INTO po FROM payouts WHERE provider_transfer_id = j.payout_id AND provider = 'bachs';
    RETURN jsonb_build_object('payout',to_jsonb(po),'investment',to_jsonb(inv));
  END IF;
  IF j.payout_id IS NULL THEN RAISE EXCEPTION 'Missing provider payout ID'; END IF;
  INSERT INTO payouts (user_id, amount, currency, mode, status, provider, provider_transfer_id, payout_phase, processed_by, notes)
    VALUES (j.user_id, j.amount, 'NGN', j.mode, p_status, 'bachs', j.payout_id, j.phase, j.actor, 'Bachs payout ' || j.reference)
    ON CONFLICT (provider_transfer_id) WHERE provider = 'bachs' AND provider_transfer_id IS NOT NULL
      DO UPDATE SET status = EXCLUDED.status, processed_at = now()
    RETURNING * INTO po;
  UPDATE bachs_payout_jobs SET status = p_status WHERE reference = p_reference;
  IF p_status = 'successful' AND j.reward_id IS NOT NULL THEN
    UPDATE bachs_referral_rewards SET status = 'successful' WHERE id = j.reward_id;
    UPDATE profiles SET referral_pending_payout = greatest(0, coalesce(referral_pending_payout,0) - j.amount),
      referral_paid_total = coalesce(referral_paid_total,0) + j.amount WHERE id = j.user_id;
  END IF;
  IF p_status = 'successful' AND inv.payout_phase = j.phase AND inv.next_payment_date = j.due_date THEN
    week_number := substring(j.phase FROM '[1-4]')::integer;
    IF week_number < 4 THEN
      UPDATE investments SET payout_phase = 'week' || (week_number + 1),
        next_payment_date = coalesce(cycle_start_date,start_date)::date + (week_number + 1) * 7
        WHERE id = inv.id RETURNING * INTO inv;
    ELSE
      UPDATE investments SET payout_phase = 'week1', cycle_count = coalesce(cycle_count,0) + 1,
        cycle_start_date = now(), next_payment_date = current_date + 7
        WHERE id = inv.id RETURNING * INTO inv;
    END IF;
  END IF;
  RETURN jsonb_build_object('payout',to_jsonb(po),'investment',to_jsonb(inv));
END $$;
CREATE OR REPLACE FUNCTION public.bachs_record_pending_payout(p_reference text, p_payout_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE j bachs_payout_jobs; po payouts;
BEGIN
  SELECT * INTO j FROM bachs_payout_jobs WHERE reference = p_reference FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown payout'; END IF;
  IF j.payout_id IS NOT NULL AND j.payout_id <> p_payout_id THEN RAISE EXCEPTION 'Payout ID mismatch'; END IF;
  IF j.status NOT IN ('successful','failed') THEN
    UPDATE bachs_payout_jobs SET payout_id = p_payout_id, status = 'pending' WHERE reference = p_reference;
  END IF;
  INSERT INTO payouts(user_id,amount,currency,mode,status,provider,provider_transfer_id,payout_phase,processed_by,notes)
    VALUES(j.user_id,j.amount,'NGN',j.mode,'pending','bachs',p_payout_id,j.phase,j.actor,'Bachs payout ' || j.reference)
    ON CONFLICT (provider_transfer_id) WHERE provider = 'bachs' AND provider_transfer_id IS NOT NULL DO NOTHING;
  SELECT * INTO po FROM payouts WHERE provider = 'bachs' AND provider_transfer_id = p_payout_id;
  RETURN jsonb_build_object('payout',to_jsonb(po));
END $$;
REVOKE ALL ON FUNCTION public.bachs_credit_payment(text,text), public.bachs_finish_payout(text,text) FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bachs_credit_payment(text,text), public.bachs_finish_payout(text,text) TO service_role;
REVOKE ALL ON FUNCTION public.bachs_record_pending_payout(text,text) FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bachs_record_pending_payout(text,text) TO service_role;
