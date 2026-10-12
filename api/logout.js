import { createHash } from 'node:crypto';
import { getDb, noStore } from './_lib/server.js';

export default async function handler(req,res){
 noStore(res);
 if(req.method!=='POST')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 res.setHeader('Set-Cookie','a08_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
 const token=(req.headers.cookie||'').match(/(?:^|;\s*)a08_session=([^;]+)/)?.[1];
 if(!token)return res.status(200).json({loggedOut:true});
 try{
  const hash=createHash('sha256').update(token).digest('hex');
  const db=getDb();
  const {error}=await db.from('a08_sessions').update({revoked_at:new Date().toISOString()}).eq('token_hash',hash).is('revoked_at',null);
  if(error)throw error;
  return res.status(200).json({loggedOut:true});
 }catch(e){console.error('logout error',e?.message);return res.status(500).json({error:'LOGOUT_FAILED'});}
}
