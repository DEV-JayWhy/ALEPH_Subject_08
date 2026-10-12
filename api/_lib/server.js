import { createClient } from '@supabase/supabase-js';

export const RP_ID = 'aleph-subject-08.vercel.app';
export const EXPECTED_ORIGIN = 'https://aleph-subject-08.vercel.app';

export function getDb() {
  const url = process.env.SUPABASE_URL;
  const secret = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !secret) throw new Error('Server database credentials are not configured');
  return createClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } });
}

export function noStore(res) {
  res.setHeader('Cache-Control', 'no-store');
}
