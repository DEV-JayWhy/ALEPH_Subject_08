import {createHash} from 'node:crypto';
import {getDb,noStore} from './_lib/server.js';
export default async function handler(req,res){
 noStore(res);
 if(!['GET','DELETE'].includes(req.method))return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 const token=(req.headers.cookie||'').match(/(?:^|;\s*)a08_session=([^;]+)/)?.[1];
 if(!token)return res.status(401).json({error:'AUTH_REQUIRED'});
 try{
  const db=getDb(),hash=createHash('sha256').update(token).digest('hex');
  const {data:session,error:se}=await db.from('a08_sessions').select('user_id').eq('token_hash',hash).is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
  if(se)throw se;
  if(!session)return res.status(401).json({error:'SESSION_INVALID'});
  const {data:keys,error:ke}=await db.from('a08_passkeys').select('id,name,created_at,last_used_at').eq('user_id',session.user_id).order('created_at');
  if(ke)throw ke;
  if(req.method==='GET')return res.status(200).json({passkeys:keys.map(({id,name,created_at,last_used_at})=>({id,name,created_at,last_used_at}))});
  const id=req.body?.id;
  if(typeof id!=='string'||!id)return res.status(400).json({error:'INVALID_PASSKEY_ID'});
  if(!keys.some(k=>k.id===id))return res.status(404).json({error:'PASSKEY_NOT_FOUND'});
  if(keys.length<=1)return res.status(409).json({error:'LAST_PASSKEY_PROTECTED'});
  const {error:de}=await db.from('a08_passkeys').delete().eq('id',id).eq('user_id',session.user_id);
  if(de)throw de;
  return res.status(200).json({deleted:true});
 }catch(e){console.error('passkey management failed',e?.message);return res.status(500).json({error:'PASSKEY_MANAGEMENT_FAILED'});}
}
