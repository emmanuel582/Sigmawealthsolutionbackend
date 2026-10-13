import type { Express, Request } from 'express';
import type { SupabaseClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';

export async function isApprovedAdmin(database: SupabaseClient, user: { id: string; email?: string; email_confirmed_at?: string }): Promise<boolean> {
  if (!user.email || !user.email_confirmed_at) return false;
  const [role, allow] = await Promise.all([
    database.from('user_roles').select('role').eq('user_id', user.id).maybeSingle(),
    database.from('admin_allowlist').select('email').eq('email', user.email.toLowerCase()).maybeSingle(),
  ]);
  return !role.error && !allow.error && role.data?.role === 'admin' && Boolean(allow.data);
}

export function secretMatches(expected: string, supplied: string): boolean {
  const a = Buffer.from(expected); const b = Buffer.from(supplied);
  return a.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

// This gate covers legacy routes as well as future additions in their namespaces.
export function mountAuthorization(app: Express, database: SupabaseClient | null, conversations: Map<string, any>) {
  app.use('/api', async (req, res, next) => {
    try {
      const path = req.path;
      if (path.startsWith('/auth/') || path.startsWith('/admin/dev/')) {
        return res.status(410).json({ message: 'Use Supabase authentication. Legacy local authentication and seed endpoints are disabled.' });
      }
      if (path.startsWith('/opay/') || path === '/admin/opay-receipts/review') return res.status(410).json({ message: 'New funding uses Bachs checkout only. Historical receipt records are read-only.' });
      const support = path.startsWith('/support/');
      const privateRoute = support || path.startsWith('/admin/') || path.startsWith('/investor/') || path.startsWith('/opay/');
      if (!privateRoute) return next();
      // These routes authenticate a dedicated runner credential themselves.
      if (['/investor/process-auto-debits','/investor/auto-debit-reminders'].includes(path)) return next();
      const wantsAdmin = path.startsWith('/admin/') && !path.startsWith('/admin/check-role/')
        || path.startsWith('/support/admin/') || req.query.as === 'admin'
        || support && (req.body?.sender === 'admin' || req.body?.role === 'admin' || req.method === 'PATCH');
      const bearer = req.get('Authorization')?.replace(/^Bearer\s+/i, '');
      let user: any = null;
      if (bearer && database) {
        const result = await database.auth.getUser(bearer);
        if (!result.error) user = result.data.user;
      }
      if (wantsAdmin) {
        if (!user) return res.status(401).json({ message: 'Sign in to continue.' });
        if (!database || !await isApprovedAdmin(database, user)) return res.status(403).json({ message: 'Administrator access required.' });
        res.locals.authUser = user;
        return next();
      }
      if (support) {
        const guest = req.get('X-Support-Token') || '';
        const id = path.match(/^\/support\/conversations\/([^/]+)/)?.[1] || req.body?.conversationId;
        const conversation = id ? conversations.get(id) : [...conversations.values()].find(c => c.guest_id === guest && !c.user_id);
        if (conversation) {
          const owned = user && conversation.user_id === user.id
            || !conversation.user_id && secretMatches(conversation.guest_id || '', guest);
          if (!owned) return res.status(403).json({ message: 'Conversation access denied.' });
        } else if (id) return res.status(404).json({ message: 'Conversation not found.' });
        if (!user && !/^guest-[0-9a-f-]{36}$/i.test(guest)) return res.status(401).json({ message: 'A private support token is required.' });
        if (req.method === 'POST' && path === '/support/conversations') {
          req.body.userId = user?.id || null;
          req.body.guestId = user ? null : guest;
          if (user) req.body.email = user.email;
        }
        res.locals.authUser = user;
        return next();
      }
      if (!user) return res.status(401).json({ message: 'Sign in to continue.' });
      const requested = path.match(/^\/investor\/(?:profile|dashboard|connect\/status)\/([^/]+)/)?.[1]
        || path.match(/^\/admin\/check-role\/([^/]+)/)?.[1] || req.body?.userId || req.body?.id;
      if (requested && requested !== user.id) return res.status(403).json({ message: 'You can only access your own account.' });
      req.query.email = user.email || '';
      if (req.body?.email !== undefined) req.body.email = user.email || '';
      res.locals.authUser = user;
      next();
    } catch {
      res.status(503).json({ message: 'Account authorization is temporarily unavailable.' });
    }
  });
}
