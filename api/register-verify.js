import { createHash } from 'node:crypto';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { getDb, RP_ID, EXPECTED_ORIGIN, noStore } from './_lib/server.js';

export default async function handler(req,res) {
  noStore(res);
  if(req.method!=='POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  try {
    const {challengeId,credential}=req.body||{};
    if(typeof challengeId!=='string'||!credential?.response?.clientDataJSON) return res.status(400).json({error:'INVALID_REQUEST'});
    const db=getDb();
    const {data:ch,error:ce}=await db.from('a08_challenges').select('id,user_id,challenge_hash,expires_at,consumed_at,purpose').eq('id',challengeId).eq('purpose','registration').maybeSingle();
    if(ce) throw ce;
    if(!ch||ch.consumed_at||new Date(ch.expires_at).getTime()<=Date.now()) return res.status(400).json({error:'CHALLENGE_INVALID'});
    const client=JSON.parse(Buffer.from(credential.response.clientDataJSON,'base64url').toString('utf8'));
    if(typeof client.challenge!=='string'||createHash('sha256').update(client.challenge).digest('hex')!==ch.challenge_hash) return res.status(400).json({error:'CHALLENGE_MISMATCH'});
    const verification=await verifyRegistrationResponse({
      response:credential,expectedChallenge:client.challenge,expectedOrigin:EXPECTED_ORIGIN,expectedRPID:RP_ID,requireUserVerification:true
    });
    if(!verification.verified||!verification.registrationInfo) return res.status(400).json({error:'VERIFICATION_FAILED'});
    // Atomic claim prevents a challenge from being reused after successful verification.
    const {data:claimed,error:claimError}=await db.from('a08_challenges').update({consumed_at:new Date().toISOString()}).eq('id',ch.id).is('consumed_at',null).gt('expires_at',new Date().toISOString()).select('id').maybeSingle();
    if(claimError) throw claimError;
    if(!claimed) return res.status(409).json({error:'CHALLENGE_REPLAY'});
    const info=verification.registrationInfo;
    const {error:pe}=await db.from('a08_passkeys').insert({
      id:info.credential.id,user_id:ch.user_id,name:'첫 번째 패스키',
      public_key:'\\x'+Buffer.from(info.credential.publicKey).toString('hex'),
      sign_count:info.credential.counter,transports:credential.response.transports||[],
      device_type:info.credentialDeviceType||null,backed_up:info.credentialBackedUp||false
    });
    if(pe) { console.error('passkey insert failed',pe.message);return res.status(500).json({error:'PASSKEY_SAVE_FAILED'}); }
    return res.status(200).json({verified:true,credentialId:info.credential.id});
  } catch(e) { console.error('registration verify failed',e?.message);return res.status(400).json({error:'REGISTRATION_VERIFICATION_FAILED'}); }
}
