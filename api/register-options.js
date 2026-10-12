import { randomBytes, createHash } from 'node:crypto';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { getDb, RP_ID, noStore } from './_lib/server.js';

export default async function handler(req,res) {
  noStore(res);
  if(req.method!=='POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  let stage='request_validation';
  try {
    const name = String(req.body?.displayName || '').trim();
    if(name.length < 2 || name.length > 50) return res.status(400).json({error:'INVALID_NAME'});
    stage='db_init';
    const db=getDb();
    // New registrations create fresh users; never let an anonymous caller claim an existing user.
    stage='user_insert';
    const {data:user,error:ue}=await db.from('a08_users').insert({display_name:name}).select('id').single();
    if(ue) { console.error('registration database insert failed', ue.code, ue.message); throw ue; }
    stage='generate_options';
    const options=await generateRegistrationOptions({
      rpName:'ALEPH Subject 08',rpID:RP_ID,
      userID:new TextEncoder().encode(user.id),userName:user.id,userDisplayName:name,
      attestationType:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'},
      supportedAlgorithmIDs:[-7,-257],timeout:60000
    });
    const hash=createHash('sha256').update(options.challenge).digest('hex');
    stage='challenge_insert';
    const {data:row,error:ce}=await db.from('a08_challenges').insert({
      user_id:user.id,challenge_hash:hash,purpose:'registration',
      expires_at:new Date(Date.now()+120000).toISOString()
    }).select('id').single();
    if(ce) throw ce;
    return res.status(200).json({options,challengeId:row.id});
  } catch(e) { console.error('registration options failed',stage,e?.message);return res.status(500).json({error:'REGISTRATION_OPTIONS_FAILED',stage,reason:e?.code==='42501'?'DB_PERMISSION':e?.code==='PGRST301'?'DB_AUTH':e?.code?.startsWith('PGRST')?'DB_API':'SERVER_ERROR'}); }
}
