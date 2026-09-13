-- Run this in Supabase SQL Editor to persist live support chat across refresh.
-- Safe to re-run (IF NOT EXISTS / DROP POLICY IF EXISTS).

CREATE TABLE IF NOT EXISTS public.support_conversations (
  id TEXT PRIMARY KEY,
  guest_id TEXT,
  user_id TEXT,
  visitor_name TEXT,
  visitor_email TEXT,
  status TEXT DEFAULT 'open',
  unread_admin INTEGER DEFAULT 0,
  unread_user INTEGER DEFAULT 0,
  last_message_at TIMESTAMPTZ,
  last_message_preview TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS support_conversations_guest_idx ON public.support_conversations (guest_id);
CREATE INDEX IF NOT EXISTS support_conversations_user_idx ON public.support_conversations (user_id);
CREATE INDEX IF NOT EXISTS support_conversations_updated_idx ON public.support_conversations (updated_at DESC);

CREATE TABLE IF NOT EXISTS public.support_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES public.support_conversations(id) ON DELETE CASCADE,
  sender TEXT NOT NULL CHECK (sender IN ('user', 'admin')),
  sender_name TEXT,
  content TEXT NOT NULL,
  status TEXT DEFAULT 'delivered',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS support_messages_conversation_idx ON public.support_messages (conversation_id, created_at);

ALTER TABLE public.support_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "support_conversations_admin_all" ON public.support_conversations;
CREATE POLICY "support_conversations_admin_all" ON public.support_conversations
  FOR ALL USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "support_messages_admin_all" ON public.support_messages;
CREATE POLICY "support_messages_admin_all" ON public.support_messages
  FOR ALL USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
