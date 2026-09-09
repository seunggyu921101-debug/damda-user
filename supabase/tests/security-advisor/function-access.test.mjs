import { PGlite } from '@electric-sql/pglite';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
const fixtures=JSON.parse(readFileSync(new URL('./function-access-fixture.json',import.meta.url),'utf8'));
const patch=readFileSync(new URL('../../operations/20260909_function_access_phase3.sql',import.meta.url),'utf8');
const uid='11111111-1111-4111-8111-111111111111';
async function fixture(env){
 const db=new PGlite();
 await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS; CREATE ROLE damda_payment_code;
 CREATE SCHEMA auth; CREATE SCHEMA extensions; CREATE SCHEMA payment_private;
 GRANT USAGE ON SCHEMA public,auth TO anon,authenticated,service_role,damda_payment_code;
 SET check_function_bodies=false;
 CREATE TABLE auth.users(id uuid PRIMARY KEY,email_confirmed_at timestamptz);
 CREATE TABLE public.user_roles(id uuid PRIMARY KEY,role text);
 CREATE TABLE public.daycares(id uuid PRIMARY KEY,status text);
 CREATE TABLE public.reservations(status text,reserved_date date,updated_at timestamptz);
 CREATE TABLE public.reservation_holds(expires_at timestamptz);
 CREATE TABLE public.products(booking_start_date date,booking_end_date date,updated_at timestamptz);
 CREATE SEQUENCE public.generated_document_number_seq;
 CREATE TABLE payment_private.configuration(boundary_activated boolean,approvals_enabled boolean);
 INSERT INTO payment_private.configuration VALUES(true,true);
 CREATE FUNCTION public.assert_payment_boundary() RETURNS void LANGUAGE sql AS $$SELECT$$;
 CREATE FUNCTION public.create_verified_payment_order(jsonb,jsonb,text) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$;
 CREATE FUNCTION public.send_alimtalk_http(text) RETURNS void LANGUAGE sql AS $$SELECT$$;
 REVOKE EXECUTE ON FUNCTION public.create_verified_payment_order(jsonb,jsonb,text),public.send_alimtalk_http(text) FROM PUBLIC;
 GRANT EXECUTE ON FUNCTION public.create_verified_payment_order(jsonb,jsonb,text) TO authenticated;
 GRANT EXECUTE ON FUNCTION public.send_alimtalk_http(text) TO service_role;
 `);
 for(const f of fixtures[env]){
  await db.exec(f.definition);
  await db.exec(`GRANT EXECUTE ON FUNCTION public.${f.identity} TO anon,authenticated,service_role`);
 }
 await db.exec(`CREATE TRIGGER approve_role AFTER UPDATE ON public.daycares FOR EACH ROW EXECUTE FUNCTION public.add_daycare_role_on_approval();
 CREATE TRIGGER confirm_email AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.auto_confirm_email();
 GRANT INSERT ON auth.users TO authenticated;
 GRANT SELECT,INSERT,UPDATE ON public.daycares TO authenticated;
 INSERT INTO public.daycares VALUES('${uid}','pending');
 INSERT INTO public.reservations VALUES('confirmed',current_date-2,now());`);
 return db;
}
for(const env of ['dev','prod']){
 test(`${env}: internal/client ACLs, existing signup triggers and cron behavior`,async()=>{
  const db=await fixture(env);
  try{
   await db.exec(patch);
   await db.exec(`SET ROLE authenticated; INSERT INTO auth.users(id) VALUES('${uid}'); UPDATE public.daycares SET status='approved' WHERE id='${uid}'; RESET ROLE;`);
   assert.equal((await db.query(`SELECT email_confirmed_at IS NOT NULL AS confirmed FROM auth.users`)).rows[0].confirmed,true);
   assert.equal((await db.query(`SELECT role FROM public.user_roles WHERE id='${uid}'`)).rows[0].role,'daycare');
   for(const role of ['anon','authenticated']){
    await db.exec(`SET ROLE ${role}`);
    for(const sql of ['SELECT public.auto_complete_reservations()',"SELECT public.next_generated_document_number('INV')","SELECT public.create_secure_payment_order('[]','{}','card')"])
     await assert.rejects(db.exec(sql),e=>e.code==='42501');
    await db.exec('RESET ROLE');
   }
   assert.equal((await db.query(`SELECT public.auto_complete_reservations() AS n`)).rows[0].n,1);
   assert.match((await db.query(`SELECT public.next_generated_document_number('INV') AS n`)).rows[0].n,/^INV-\d{8}-000001$/);
   if(env==='prod') assert.equal((await db.query('SELECT public.renew_expiring_product_booking_windows() AS n')).rows[0].n,0);
   assert.equal((await db.query(`SELECT has_function_privilege('damda_payment_code','public.create_secure_payment_order(jsonb,jsonb,text)','EXECUTE') AS allowed`)).rows[0].allowed,true);
   await db.exec('SET ROLE anon');
   await assert.rejects(db.exec('SELECT public.cleanup_expired_holds()'),e=>e.code==='42501');
   await db.exec('RESET ROLE; SET ROLE authenticated; SELECT public.cleanup_expired_holds(); RESET ROLE;');
   const rollback=readFileSync(new URL(`../../operations/20260909_function_access_phase3_rollback_${env}.sql`,import.meta.url),'utf8');
   await db.exec(rollback);
   assert.equal((await db.query(`SELECT has_function_privilege('anon','public.auto_complete_reservations()','EXECUTE') AS allowed`)).rows[0].allowed,true);
   await db.exec(patch); await db.exec(patch);
  }finally{await db.close();}
 });
}
test('unreviewed function aborts without changing earlier ACLs',async()=>{
 const db=await fixture('prod');
 try{
  await db.exec(`CREATE OR REPLACE FUNCTION public.cleanup_expired_holds() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$BEGIN NULL; END$$;`);
  await assert.rejects(db.exec(patch),/FUNCTION_ACCESS_REVIEW_REQUIRED/);
  await db.exec('ROLLBACK');
  assert.equal((await db.query(`SELECT has_function_privilege('anon','public.auto_complete_reservations()','EXECUTE') AS allowed`)).rows[0].allowed,true);
 }finally{await db.close();}
});
