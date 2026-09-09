import {PGlite} from '@electric-sql/pglite';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
const fixtures=JSON.parse(readFileSync(new URL('./storage-policy-fixture.json',import.meta.url),'utf8'));
const uid='11111111-1111-4111-8111-111111111111', other='22222222-2222-4222-8222-222222222222';
const owner='33333333-3333-4333-8333-333333333333';
const quote=s=>'"'+s.replaceAll('"','""')+'"';
async function as(db,role,user='',kind=''){
 await db.exec('RESET ROLE');
 await db.query("SELECT set_config('test.uid',$1,false),set_config('test.kind',$2,false)",[user,kind]);
 await db.exec(`SET ROLE ${role}`);
}
for(const env of ['dev','prod'])test(`${env}: scoped public files preserve signup, review, business and admin operations`,async()=>{
 const db=new PGlite();
 try{
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
   CREATE SCHEMA auth; CREATE SCHEMA storage;
   GRANT USAGE ON SCHEMA public,auth,storage TO anon,authenticated,service_role;
   CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql AS $$SELECT nullif(current_setting('test.uid',true),'')::uuid$$;
   CREATE FUNCTION storage.foldername(text) RETURNS text[] LANGUAGE sql AS $$SELECT (string_to_array($1,'/'))[1:array_length(string_to_array($1,'/'),1)-1]$$;
   CREATE FUNCTION public.is_active_admin() RETURNS boolean LANGUAGE sql AS $$SELECT current_setting('test.kind',true)='admin'$$;
   CREATE FUNCTION public.is_daycare() RETURNS boolean LANGUAGE sql AS $$SELECT current_setting('test.kind',true)='daycare'$$;
   CREATE FUNCTION public.current_business_owner_id() RETURNS uuid LANGUAGE sql AS $$SELECT CASE WHEN current_setting('test.kind',true)='business' THEN '${owner}'::uuid END$$;
   CREATE FUNCTION public.assert_payment_boundary() RETURNS void LANGUAGE sql AS $$SELECT$$;
   CREATE TABLE public.daycares(id uuid,deleted_at timestamptz);
   CREATE TABLE public.business_owners(id uuid,name varchar,auth_user_id uuid,status varchar);
   INSERT INTO public.daycares VALUES('${uid}',NULL),('${other}',NULL);
   CREATE TABLE storage.buckets(id text,public boolean);
   INSERT INTO storage.buckets VALUES('public',true);
   CREATE TABLE storage.objects(id integer GENERATED ALWAYS AS IDENTITY,bucket_id text,name text,owner_id text);
   ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
   GRANT SELECT,INSERT,UPDATE,DELETE ON storage.objects TO anon,authenticated,service_role;
   GRANT USAGE ON SEQUENCE storage.objects_id_seq TO anon,authenticated,service_role;
   GRANT SELECT ON public.daycares,public.business_owners TO authenticated;
   INSERT INTO storage.objects(bucket_id,name) VALUES('public','vendor-logos/admin-image.png'),('public','daycare-documents/${other}/license.png');`);
  for(const p of fixtures[env]){
   let sql=`CREATE POLICY ${quote(p.policyname)} ON storage.objects AS ${p.permissive} FOR ${p.cmd} TO ${p.roles.map(quote).join(',')}`;
   if(p.qual)sql+=` USING (${p.qual})`; if(p.with_check)sql+=` WITH CHECK (${p.with_check})`;
   await db.exec(sql);
  }
  const sql=readFileSync(new URL(`../../operations/20260909_storage_public_access_${env}.sql`,import.meta.url),'utf8');
  await db.exec(sql);
  await as(db,'anon'); assert.equal((await db.query('SELECT * FROM storage.objects')).rows.length,0);
  await as(db,'authenticated',uid,'pending');
  await db.query("INSERT INTO storage.objects(bucket_id,name) VALUES('public',$1)",[`daycare-documents/${uid}/license.png`]);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM storage.objects')).rows[0].n,1);
  await assert.rejects(db.query("INSERT INTO storage.objects(bucket_id,name) VALUES('public',$1)",[`daycare-documents/${other}/forged.png`]),e=>e.code==='42501');
  assert.equal((await db.query("DELETE FROM storage.objects WHERE name='vendor-logos/admin-image.png' RETURNING id")).rows.length,0);
  await assert.rejects(db.query("UPDATE storage.objects SET name='vendor-logos/takeover.png' WHERE name=$1",[`daycare-documents/${uid}/license.png`]),e=>e.code==='42501');
  await as(db,'authenticated',uid,'daycare');
  await db.query("INSERT INTO storage.objects(bucket_id,name) VALUES('public',$1)",[`reviews/${uid}/review.png`]);
  await as(db,'authenticated',uid,'business');
  await db.query("INSERT INTO storage.objects(bucket_id,name) VALUES('public',$1)",[`product-images/${owner}/photo.png`]);
  await assert.rejects(db.query("INSERT INTO storage.objects(bucket_id,name) VALUES('public',$1)",[`product-images/${other}/photo.png`]),e=>e.code==='42501');
  assert.equal((await db.query("DELETE FROM storage.objects WHERE name=$1 RETURNING id",[`product-images/${owner}/photo.png`])).rows.length,1);
  await as(db,'authenticated',uid,'admin');
  await db.exec("UPDATE storage.objects SET name='vendor-logos/new.png' WHERE name='vendor-logos/admin-image.png'");
  assert.equal((await db.query("SELECT count(*)::int AS n FROM storage.objects WHERE name='vendor-logos/new.png'")).rows[0].n,1);
  await as(db,'postgres');
  assert.equal((await db.query("SELECT public FROM storage.buckets WHERE id='public'")).rows[0].public,true);
  await db.exec(readFileSync(new URL(`../../operations/20260909_storage_public_access_rollback_${env}.sql`,import.meta.url),'utf8'));
  await db.exec(sql);
 }finally{await db.close();}
});
