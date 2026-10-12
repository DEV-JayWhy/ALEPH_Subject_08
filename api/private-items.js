import { createHash } from 'node:crypto';
import { getDb } from './_lib/server.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  const match = (req.headers.cookie || '').match(/(?:^|;\s*)a08_session=([^;]+)/);
  if (!match) return res.status(401).json({ error: 'AUTH_REQUIRED' });

  try {
    const db = getDb();
    const tokenHash = createHash('sha256').update(match[1]).digest('hex');
    const { data: session, error: sessionError } = await db
      .from('a08_sessions').select('user_id')
      .eq('token_hash', tokenHash)
      .is('revoked_at', null)
      .gt('expires_at', new Date().toISOString()).maybeSingle();
    if (sessionError) throw sessionError;
    if (!session) return res.status(401).json({ error: 'SESSION_INVALID' });

    const { data: items, error: itemsError } = await db
      .from('a08_private_items').select('id,category,title,content')
      .eq('user_id', session.user_id).order('created_at');
    if (itemsError) throw itemsError;
    return res.status(200).json({ items: items || [] });
  } catch (error) {
    console.error('Private data request failed', error?.message);
    return res.status(500).json({ error: 'PRIVATE_ITEMS_FAILED' });
  }
}
