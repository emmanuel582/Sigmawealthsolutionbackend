-- Run after schema.sql and bachs.sql. Browser credentials may read their RLS
-- records, but cannot invent deposits, payouts, roles or verified destinations.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['profiles','user_roles','admin_allowlist','bank_details','card_details','investments','payments','payouts','opay_receipts','platform_settings','notifications','activity_log','support_conversations','support_messages'] LOOP
    IF to_regclass('public.' || t) IS NOT NULL THEN
      EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON TABLE public.%I FROM PUBLIC, anon, authenticated',t);
      EXECUTE format('GRANT ALL ON TABLE public.%I TO service_role',t);
    END IF;
  END LOOP;
END $$;
GRANT UPDATE (name, phone) ON public.profiles TO authenticated;

-- Upgrade existing admin RLS checks to the confirmed Auth identity, rather than
-- editable profile data. The guard also lets isolated ledger tests omit Auth.
DO $$ BEGIN
  IF to_regclass('auth.users') IS NOT NULL THEN
    EXECUTE $definition$
      CREATE OR REPLACE FUNCTION public.is_authorized_admin(_user_id uuid)
      RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $fn$
        SELECT EXISTS (SELECT 1 FROM public.user_roles r
          JOIN auth.users u ON u.id=r.user_id
          JOIN public.admin_allowlist a ON lower(a.email)=lower(u.email)
          WHERE r.user_id=_user_id AND r.role='admin' AND u.email_confirmed_at IS NOT NULL);
      $fn$;
    $definition$;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.bachs_storage_health()
RETURNS jsonb LANGUAGE sql STABLE SET search_path = public AS $$
  SELECT jsonb_build_object('schemaVersion',2,'financialWritesRestricted',
    NOT has_table_privilege('authenticated','public.payments','INSERT')
    AND NOT has_table_privilege('authenticated','public.investments','INSERT')
    AND NOT has_table_privilege('authenticated','public.bank_details','UPDATE')
    AND NOT has_column_privilege('authenticated','public.profiles','total_invested','UPDATE')
    AND NOT has_table_privilege('authenticated','public.user_roles','UPDATE')
    AND NOT has_function_privilege('authenticated','public.bachs_credit_payment(text,text)','EXECUTE'));
$$;
REVOKE ALL ON FUNCTION public.bachs_storage_health() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.bachs_storage_health() TO service_role;
