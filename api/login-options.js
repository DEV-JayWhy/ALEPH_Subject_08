import { randomBytes, createHash } from 'node:crypto';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getDb, RP_ID, noStore } from './_lib/server.js';
export default async function handler(req,res){
 noStore(res);
 if(req.method!=='POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 try{
  const db=getDb();
  const options=await generateAuthenticationOptions({rpID:RP_ID,userVerification:'required',timeout:60000});
  const challengeHash=createHash('sha256').update(options.challenge).digest('hex');
  const {data,error}=await db.from('a08_challenges').insert({challenge_hash:challengeHash,purpose:'authentication',expires_at:new Date(Date.now()+120000).toISOString()}).select('id').single();
  if(error)throw error;
  return res.status(200).json({options,challengeId:data.id});
 }catch(e){console.error('login options error',e?.message);return res.status(500).json({error:'LOGIN_OPTIONS_FAILED'});}
}