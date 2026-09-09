import {PGlite} from '@electric-sql/pglite';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
const patch=readFileSync(new URL('../../operations/20260909_rpc_authorization_guards.sql',import.meta.url),'utf8');
const fixture=JSON.parse(readFileSync(new URL('./function-access-fixture.json',import.meta.url),'utf8')).prod;
const user='11111111-1111-4111-8111-111111111111', business='22222222-2222-4222-8222-222222222222', owner='33333333-3333-4333-8333-333333333333';
test('null business ownership and inactive admins are denied; owner deletion and active admin guard remain valid',async()=>{
 const db=new PGlite();
 try{
  await db.exec(`CREATE ROLE authenticated; CREATE SCHEMA auth;
   CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql AS $$SELECT '${user}'::uuid$$;
   CREATE FUNCTION public.current_business_owner_id() RETURNS uuid LANGUAGE sql AS $$SELECT nullif(current_setting('test.owner',true),'')::uuid$$;
   CREATE TABLE businesses(id uuid,business_owner_id uuid,name text,is_primary boolean);
   CREATE TABLE products(business_id uuid); CREATE TABLE reservations(business_id uuid);
   CREATE TABLE admins(id uuid,is_active boolean);
   CREATE TABLE partner_onboardings(id uuid); CREATE TABLE business_owner_signup_requests(id uuid);
   CREATE FUNCTION public.assert_payment_boundary() RETURNS void LANGUAGE sql AS $$SELECT$$;
   GRANT USAGE ON SCHEMA public,auth TO authenticated;
   SET check_function_bodies=false;
   INSERT INTO businesses VALUES('${business}','${owner}','Local fixture',false);
   INSERT INTO admins VALUES('${user}',false);`);
  for(const name of ['delete_business_safely','approve_partner_onboarding'])await db.exec(fixture.find(f=>f.name===name).definition);
  // Demonstrate the old NULL condition bypass, then roll the test deletion back.
  await db.exec(`BEGIN; SET LOCAL ROLE authenticated; SELECT delete_business_safely('${business}','Local fixture');`);
  await db.exec('RESET ROLE'); assert.equal((await db.query('SELECT count(*)::int AS n FROM businesses')).rows[0].n,0);
  await db.exec('ROLLBACK'); await db.exec(patch);
  await db.exec('SET ROLE authenticated');
  await assert.rejects(db.exec(`SELECT delete_business_safely('${business}','Local fixture')`),/BUSINESS_ACCESS_DENIED/);
  await assert.rejects(db.exec(`SELECT approve_partner_onboarding('${business}')`),/관리자만 입점을 승인/);
  await db.exec('RESET ROLE');
  await db.exec(`UPDATE admins SET is_active=true; SET ROLE authenticated;`);
  await assert.rejects(db.exec(`SELECT approve_partner_onboarding('${business}')`),/입점 신청을 찾을 수 없습니다/);
  await db.exec(`RESET ROLE; UPDATE admins SET is_active=false; SET test.owner='${owner}'; SET ROLE authenticated;`);
  assert.equal((await db.query(`SELECT delete_business_safely('${business}','Local fixture') AS result`)).rows[0].result.success,true);
 }finally{await db.close();}
});
