import { createHash } from 'node:crypto';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { getDb, RP_ID, noStore } from './_lib/server.js';

export default async function handler(req,res){
 noStore(res);
 if(req.method!=='POST')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 const token=(req.headers.cookie||'').match(/(?:^|;\s*)a08_session=([^;]+)/)?.[1];
 if(!token)return res.status(401).json({error:'AUTH_REQUIRED'});
 try{
  const db=getDb();
  const hash=createHash('sha256').update(token).digest('hex');
  const {data:session,error:se}=await db.from('a08_sessions').select('user_id').eq('token_hash',hash).is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
  if(se)throw se;
  if(!session)return res.status(401).json({error:'SESSION_INVALID'});
  const {data:user,error:ue}=await db.from('a08_users').select('id,display_name').eq('id',session.user_id).single();
  if(ue)throw ue;
  const {data:keys,error:ke}=await db.from('a08_passkeys').select('id,transports').eq('user_id',user.id);
  if(ke)throw ke;
  if(keys.length>=2)return res.status(409).json({error:'PASSKEY_LIMIT_REACHED'});
  const options=await generateRegistrationOptions({
   rpName:'ALEPH Subject 08',rpID:RP_ID,
   userID:new TextEncoder().encode(user.id),userName:user.id,userDisplayName:user.display_name,
   attestationType:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'},
   supportedAlgorithmIDs:[-7,-257],timeout:60000,
   excludeCredentials:keys.map(k=>({id:k.id,transports:k.transports||[]}))
  });
  const challengeHash=createHash('sha256').update(options.challenge).digest('hex');
  const {data:challenge,error:ce}=await db.from('a08_challenges').insert({
   user_id:user.id,challenge_hash:challengeHash,purpose:'registration',
   expires_at:new Date(Date.now()+120000).toISOString()
  }).select('id').single();
  if(ce)throw ce;
  return res.status(200).json({options,challengeId:challenge.id});
 }catch(e){console.error('add passkey error',e?.message);return res.status(500).json({error:'ADD_PASSKEY_OPTIONS_FAILED'});}
}
