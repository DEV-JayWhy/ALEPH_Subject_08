import { randomBytes, createHash } from 'node:crypto';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getDb, RP_ID, EXPECTED_ORIGIN, noStore } from './_lib/server.js';
const digest=value=>createHash('sha256').update(value).digest('hex');

export default async function handler(req,res){
  noStore(res);
  if(req.method!=='POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  try {
    const {challengeId,credential}=req.body||{};
    if(typeof challengeId!=='string'||typeof credential?.id!=='string'||!credential?.response?.clientDataJSON) return res.status(400).json({error:'INVALID_REQUEST'});
    const db=getDb();
    const {data:ch,error:ce}=await db.from('a08_challenges').select('id,challenge_hash,consumed_at,expires_at').eq('id',challengeId).eq('purpose','authentication').maybeSingle();
    if(ce)throw ce;
    if(!ch||ch.consumed_at||Date.parse(ch.expires_at)<=Date.now())return res.status(400).json({error:'CHALLENGE_INVALID'});
    const client=JSON.parse(Buffer.from(credential.response.clientDataJSON,'base64url').toString('utf8'));
    if(typeof client.challenge!=='string'||digest(client.challenge)!==ch.challenge_hash)return res.status(400).json({error:'CHALLENGE_MISMATCH'});
    const {data:key,error:ke}=await db.from('a08_passkeys').select('id,user_id,public_key,sign_count,transports').eq('id',credential.id).maybeSingle();
    if(ke)throw ke;
    if(!key)return res.status(401).json({error:'UNKNOWN_CREDENTIAL'});
    const hex=key.public_key.startsWith('\\x')?key.public_key.slice(2):key.public_key;
    const result=await verifyAuthenticationResponse({
      response:credential,expectedChallenge:client.challenge,
      expectedOrigin:EXPECTED_ORIGIN,expectedRPID:RP_ID,requireUserVerification:true,
      credential:{id:key.id,publicKey:Buffer.from(hex,'hex'),counter:Number(key.sign_count),transports:key.transports||[]}
    });
    if(!result.verified)return res.status(401).json({error:'AUTHENTICATION_FAILED'});
    const {data:claimed,error:claimError}=await db.from('a08_challenges').update({consumed_at:new Date().toISOString()}).eq('id',ch.id).is('consumed_at',null).gt('expires_at',new Date().toISOString()).select('id').maybeSingle();
    if(claimError)throw claimError;
    if(!claimed)return res.status(409).json({error:'CHALLENGE_REPLAY'});
    const {error:ue}=await db.from('a08_passkeys').update({sign_count:result.authenticationInfo.newCounter,last_used_at:new Date().toISOString()}).eq('id',key.id);
    if(ue)throw ue;
    const token=randomBytes(32).toString('base64url');
    const {error:se}=await db.from('a08_sessions').insert({user_id:key.user_id,token_hash:digest(token),expires_at:new Date(Date.now()+3600000).toISOString()});
    if(se)throw se;
    res.setHeader('Set-Cookie','a08_session='+token+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600');
    return res.status(200).json({authenticated:true});
  }catch(e){
    console.error('login verification error',e?.message);
    return res.status(400).json({error:'LOGIN_VERIFICATION_FAILED'});
  }
}
