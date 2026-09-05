-- ==============================================================================
-- APEX CAPITAL: Supabase Postgres Schema & Row Level Security (RLS)
-- Run this in your Supabase SQL Editor to set up all tables and security policies.
-- ==============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. PROFILES TABLE (Strict 1-to-1 relationship with auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  total_invested NUMERIC(15, 2) DEFAULT 0.00,
  current_phase TEXT DEFAULT 'None',
  payment_plan_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. USER ROLES TABLE (Separate from auth.users metadata for secure authorization)
CREATE TABLE IF NOT EXISTS public.user_roles (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('investor', 'admin')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2B. ADMIN ALLOWLIST TABLE (Hard server-side allowlist of pre-approved email addresses)
-- Editable directly in Supabase Table Editor by the system owner. No in-app editing allowed.
CREATE TABLE IF NOT EXISTS public.admin_allowlist (
  email TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed initial approved administrator email
INSERT INTO public.admin_allowlist (email)
VALUES ('cmyrachrist72@gmail.com')
ON CONFLICT (email) DO NOTHING;

-- 3. BANK DETAILS TABLE (For Payouts / Flutterwave Beneficiaries)
CREATE TABLE IF NOT EXISTS public.bank_details (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  account_number TEXT NOT NULL,
  bank_code TEXT NOT NULL,
  bank_name TEXT NOT NULL,
  account_name TEXT NOT NULL,
  flutterwave_beneficiary_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. CARD DETAILS TABLE (Tokenized via Flutterwave â€” NEVER stores full card numbers)
CREATE TABLE IF NOT EXISTS public.card_details (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  flutterwave_card_token TEXT NOT NULL,
  card_last4 TEXT NOT NULL,
  card_brand TEXT NOT NULL,
  card_exp_month TEXT,
  card_exp_year TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. INVESTMENTS TABLE
CREATE TABLE IF NOT EXISTS public.investments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  amount NUMERIC(15, 2) NOT NULL,
  phase TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('auto', 'one-time', 'opay')),
  status TEXT NOT NULL CHECK (status IN ('active', 'completed', 'paused', 'cancelled', 'pending')),
  start_date TIMESTAMPTZ DEFAULT NOW(),
  next_payment_date DATE,
  cycle_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. PAYMENTS TABLE (Contribution transactions)
CREATE TABLE IF NOT EXISTS public.payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  amount NUMERIC(15, 2) NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('card', 'card_token', 'auto_debit', 'opay_transfer')),
  flutterwave_tx_ref TEXT UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('successful', 'pending', 'failed')),
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. PAYOUTS TABLE (Disbursements to investors)
CREATE TABLE IF NOT EXISTS public.payouts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  amount NUMERIC(15, 2) NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('automatic', 'manual')),
  status TEXT NOT NULL CHECK (status IN ('successful', 'pending', 'failed')),
  flutterwave_transfer_id TEXT,
  processed_at TIMESTAMPTZ DEFAULT NOW(),
  processed_by TEXT,
  notes TEXT
);

-- 8. OPAY RECEIPTS TABLE (Manual transfers receipt verification)
CREATE TABLE IF NOT EXISTS public.opay_receipts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  receipt_image_url TEXT NOT NULL,
  amount NUMERIC(15, 2) NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by TEXT,
  admin_notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ
);

-- 9. NOTIFICATIONS TABLE
CREATE TABLE IF NOT EXISTS public.notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  audience TEXT NOT NULL,
  target_user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  icon TEXT,
  image_url TEXT,
  sent_at TIMESTAMPTZ DEFAULT NOW(),
  delivery_status TEXT DEFAULT 'sent'
);

-- Optional columns for existing projects
ALTER TABLE public.notifications ADD COLUMN IF NOT EXISTS icon TEXT;
ALTER TABLE public.notifications ADD COLUMN IF NOT EXISTS image_url TEXT;

-- 10. ACTIVITY LOG TABLE
CREATE TABLE IF NOT EXISTS public.activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT NOT NULL,
  amount NUMERIC(15, 2),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 11. PLATFORM SETTINGS TABLE
CREATE TABLE IF NOT EXISTS public.platform_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 12. TESTIMONIALS TABLE (Left empty until real reviews are available)
CREATE TABLE IF NOT EXISTS public.testimonials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT,
  photo_url TEXT,
  quote TEXT,
  rating INTEGER CHECK (rating >= 1 AND rating <= 5),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default platform settings
INSERT INTO public.platform_settings (key, value)
VALUES 
  ('payout_mode', '{"mode": "manual", "updated_by": "System Initializer"}'::jsonb),
  ('payout_schedule', '{"interval": "daily", "auto_run_hour_utc": 9}'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- Enable RLS on every table
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bank_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.opay_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.testimonials ENABLE ROW LEVEL SECURITY;

-- ==============================================================================
-- POSTGRES HELPER FUNCTIONS
-- ==============================================================================

-- Two-layer Admin Verification Function:
-- 1. Must have role = 'admin' in user_roles
-- 2. Must have their email address listed in admin_allowlist
CREATE OR REPLACE FUNCTION public.is_authorized_admin(_user_id uuid)
RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 
    FROM public.user_roles ur
    LEFT JOIN public.profiles p ON p.id = ur.user_id
    LEFT JOIN auth.users u ON u.id = ur.user_id
    JOIN public.admin_allowlist al ON (
      LOWER(al.email) = LOWER(p.email) OR 
      LOWER(al.email) = LOWER(u.email) OR
      LOWER(al.email) = LOWER(COALESCE(auth.jwt()->>'email', ''))
    )
    WHERE ur.user_id = _user_id AND ur.role = 'admin'
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Helper function to check role from user_roles table securely
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text)
RETURNS boolean AS $$
BEGIN
  IF _role = 'admin' THEN
    RETURN public.is_authorized_admin(_user_id);
  ELSE
    RETURN EXISTS (
      SELECT 1 FROM public.user_roles
      WHERE user_id = _user_id AND role = _role
    );
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create a profile and assign default investor role on auth signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1))
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    name = COALESCE(EXCLUDED.name, public.profiles.name),
    updated_at = NOW();

  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'investor')
  ON CONFLICT (user_id) DO NOTHING;

  INSERT INTO public.activity_log (actor, action, details)
  VALUES (
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
    'SIGNUP',
    'New investor account registered'
  );

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach trigger to auth.users
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================
-- Drop-then-create so this file can be re-run safely.

-- 0. ADMIN_ALLOWLIST POLICIES
-- Only service_role (backend) and verified admins can view; strictly NO in-app insertion/updates/deletions.
-- Modifications must only occur directly through Supabase Table Editor / SQL Editor.
DROP POLICY IF EXISTS "admin_allowlist_select_admin" ON public.admin_allowlist;
CREATE POLICY "admin_allowlist_select_admin" ON public.admin_allowlist FOR SELECT USING (public.is_authorized_admin(auth.uid()));

-- 1. PROFILES POLICIES
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own" ON public.profiles FOR SELECT USING (auth.uid() = id);
DROP POLICY IF EXISTS "profiles_select_admin" ON public.profiles;
CREATE POLICY "profiles_select_admin" ON public.profiles FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "profiles_insert_own" ON public.profiles;
CREATE POLICY "profiles_insert_own" ON public.profiles FOR INSERT WITH CHECK (auth.uid() = id);
DROP POLICY IF EXISTS "profiles_insert_admin" ON public.profiles;
CREATE POLICY "profiles_insert_admin" ON public.profiles FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own" ON public.profiles FOR UPDATE USING (auth.uid() = id);
DROP POLICY IF EXISTS "profiles_update_admin" ON public.profiles;
CREATE POLICY "profiles_update_admin" ON public.profiles FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "profiles_delete_admin" ON public.profiles;
CREATE POLICY "profiles_delete_admin" ON public.profiles FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 2. USER_ROLES POLICIES (Read own role or admin read all, only admin or trigger can modify)
DROP POLICY IF EXISTS "user_roles_select_own" ON public.user_roles;
CREATE POLICY "user_roles_select_own" ON public.user_roles FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "user_roles_select_admin" ON public.user_roles;
CREATE POLICY "user_roles_select_admin" ON public.user_roles FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "user_roles_insert_admin" ON public.user_roles;
CREATE POLICY "user_roles_insert_admin" ON public.user_roles FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "user_roles_update_admin" ON public.user_roles;
CREATE POLICY "user_roles_update_admin" ON public.user_roles FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "user_roles_delete_admin" ON public.user_roles;
CREATE POLICY "user_roles_delete_admin" ON public.user_roles FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 3. BANK_DETAILS POLICIES
DROP POLICY IF EXISTS "bank_details_select_own" ON public.bank_details;
CREATE POLICY "bank_details_select_own" ON public.bank_details FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "bank_details_select_admin" ON public.bank_details;
CREATE POLICY "bank_details_select_admin" ON public.bank_details FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "bank_details_insert_own" ON public.bank_details;
CREATE POLICY "bank_details_insert_own" ON public.bank_details FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "bank_details_insert_admin" ON public.bank_details;
CREATE POLICY "bank_details_insert_admin" ON public.bank_details FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "bank_details_update_own" ON public.bank_details;
CREATE POLICY "bank_details_update_own" ON public.bank_details FOR UPDATE USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "bank_details_update_admin" ON public.bank_details;
CREATE POLICY "bank_details_update_admin" ON public.bank_details FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "bank_details_delete_admin" ON public.bank_details;
CREATE POLICY "bank_details_delete_admin" ON public.bank_details FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 4. CARD_DETAILS POLICIES
DROP POLICY IF EXISTS "card_details_select_own" ON public.card_details;
CREATE POLICY "card_details_select_own" ON public.card_details FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "card_details_select_admin" ON public.card_details;
CREATE POLICY "card_details_select_admin" ON public.card_details FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "card_details_insert_own" ON public.card_details;
CREATE POLICY "card_details_insert_own" ON public.card_details FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "card_details_insert_admin" ON public.card_details;
CREATE POLICY "card_details_insert_admin" ON public.card_details FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "card_details_update_own" ON public.card_details;
CREATE POLICY "card_details_update_own" ON public.card_details FOR UPDATE USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "card_details_update_admin" ON public.card_details;
CREATE POLICY "card_details_update_admin" ON public.card_details FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "card_details_delete_admin" ON public.card_details;
CREATE POLICY "card_details_delete_admin" ON public.card_details FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 5. INVESTMENTS POLICIES
DROP POLICY IF EXISTS "investments_select_own" ON public.investments;
CREATE POLICY "investments_select_own" ON public.investments FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "investments_select_admin" ON public.investments;
CREATE POLICY "investments_select_admin" ON public.investments FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "investments_insert_own" ON public.investments;
CREATE POLICY "investments_insert_own" ON public.investments FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "investments_insert_admin" ON public.investments;
CREATE POLICY "investments_insert_admin" ON public.investments FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "investments_update_admin" ON public.investments;
CREATE POLICY "investments_update_admin" ON public.investments FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "investments_delete_admin" ON public.investments;
CREATE POLICY "investments_delete_admin" ON public.investments FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 6. PAYMENTS POLICIES
DROP POLICY IF EXISTS "payments_select_own" ON public.payments;
CREATE POLICY "payments_select_own" ON public.payments FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "payments_select_admin" ON public.payments;
CREATE POLICY "payments_select_admin" ON public.payments FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "payments_insert_own" ON public.payments;
CREATE POLICY "payments_insert_own" ON public.payments FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "payments_insert_admin" ON public.payments;
CREATE POLICY "payments_insert_admin" ON public.payments FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "payments_update_admin" ON public.payments;
CREATE POLICY "payments_update_admin" ON public.payments FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "payments_delete_admin" ON public.payments;
CREATE POLICY "payments_delete_admin" ON public.payments FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 7. PAYOUTS POLICIES
DROP POLICY IF EXISTS "payouts_select_own" ON public.payouts;
CREATE POLICY "payouts_select_own" ON public.payouts FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "payouts_select_admin" ON public.payouts;
CREATE POLICY "payouts_select_admin" ON public.payouts FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "payouts_insert_admin" ON public.payouts;
CREATE POLICY "payouts_insert_admin" ON public.payouts FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "payouts_update_admin" ON public.payouts;
CREATE POLICY "payouts_update_admin" ON public.payouts FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "payouts_delete_admin" ON public.payouts;
CREATE POLICY "payouts_delete_admin" ON public.payouts FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 8. OPAY_RECEIPTS POLICIES
DROP POLICY IF EXISTS "opay_receipts_select_own" ON public.opay_receipts;
CREATE POLICY "opay_receipts_select_own" ON public.opay_receipts FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "opay_receipts_select_admin" ON public.opay_receipts;
CREATE POLICY "opay_receipts_select_admin" ON public.opay_receipts FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "opay_receipts_insert_own" ON public.opay_receipts;
CREATE POLICY "opay_receipts_insert_own" ON public.opay_receipts FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "opay_receipts_update_admin" ON public.opay_receipts;
CREATE POLICY "opay_receipts_update_admin" ON public.opay_receipts FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "opay_receipts_delete_admin" ON public.opay_receipts;
CREATE POLICY "opay_receipts_delete_admin" ON public.opay_receipts FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 9. NOTIFICATIONS POLICIES
DROP POLICY IF EXISTS "notifications_select_target" ON public.notifications;
CREATE POLICY "notifications_select_target" ON public.notifications FOR SELECT USING (audience = 'all' OR target_user_id = auth.uid());
DROP POLICY IF EXISTS "notifications_select_admin" ON public.notifications;
CREATE POLICY "notifications_select_admin" ON public.notifications FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "notifications_insert_admin" ON public.notifications;
CREATE POLICY "notifications_insert_admin" ON public.notifications FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "notifications_update_admin" ON public.notifications;
CREATE POLICY "notifications_update_admin" ON public.notifications FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "notifications_delete_admin" ON public.notifications;
CREATE POLICY "notifications_delete_admin" ON public.notifications FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 10. ACTIVITY_LOG POLICIES
DROP POLICY IF EXISTS "activity_log_select_admin" ON public.activity_log;
CREATE POLICY "activity_log_select_admin" ON public.activity_log FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "activity_log_insert_admin" ON public.activity_log;
CREATE POLICY "activity_log_insert_admin" ON public.activity_log FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "activity_log_delete_admin" ON public.activity_log;
CREATE POLICY "activity_log_delete_admin" ON public.activity_log FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 11. PLATFORM_SETTINGS POLICIES
DROP POLICY IF EXISTS "platform_settings_select_all" ON public.platform_settings;
CREATE POLICY "platform_settings_select_all" ON public.platform_settings FOR SELECT USING (true);
DROP POLICY IF EXISTS "platform_settings_insert_admin" ON public.platform_settings;
CREATE POLICY "platform_settings_insert_admin" ON public.platform_settings FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "platform_settings_update_admin" ON public.platform_settings;
CREATE POLICY "platform_settings_update_admin" ON public.platform_settings FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "platform_settings_delete_admin" ON public.platform_settings;
CREATE POLICY "platform_settings_delete_admin" ON public.platform_settings FOR DELETE USING (public.has_role(auth.uid(), 'admin'));

-- 12. TESTIMONIALS POLICIES
DROP POLICY IF EXISTS "testimonials_select_all" ON public.testimonials;
CREATE POLICY "testimonials_select_all" ON public.testimonials FOR SELECT USING (true);
DROP POLICY IF EXISTS "testimonials_admin_write" ON public.testimonials;
CREATE POLICY "testimonials_admin_write" ON public.testimonials FOR INSERT WITH CHECK (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "testimonials_update_admin" ON public.testimonials;
CREATE POLICY "testimonials_update_admin" ON public.testimonials FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));
DROP POLICY IF EXISTS "testimonials_delete_admin" ON public.testimonials;
CREATE POLICY "testimonials_delete_admin" ON public.testimonials FOR DELETE USING (public.has_role(auth.uid(), 'admin'));
