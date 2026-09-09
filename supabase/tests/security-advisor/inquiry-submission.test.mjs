import {PGlite} from '@electric-sql/pglite';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
const patch=readFileSync(new URL('../../operations/20260909_partner_inquiry_submission.sql',import.meta.url),'utf8');
test('public pending inquiry succeeds, forged reviews and invalid submissions fail, admin review remains available',async()=>{
 const db=new PGlite();
 try{
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated;
   CREATE FUNCTION public.is_active_admin() RETURNS boolean LANGUAGE sql AS $$SELECT current_setting('test.admin',true)='true'$$;
   CREATE TABLE partner_inquiries(id uuid DEFAULT gen_random_uuid(),name text,business_number text,representative text,contact_name text,contact_phone text,email text,program_types text,description text,status text DEFAULT 'pending',reviewed_by uuid,reviewed_at timestamptz,rejection_reason text,memo text);
   ALTER TABLE partner_inquiries ENABLE ROW LEVEL SECURITY;
   GRANT SELECT,INSERT,UPDATE,DELETE ON partner_inquiries TO anon,authenticated;
   CREATE POLICY "Anyone can insert partner inquiries" ON partner_inquiries FOR INSERT TO anon,authenticated WITH CHECK(true);
   CREATE POLICY "Admins manage partner inquiries" ON partner_inquiries FOR ALL TO authenticated USING(is_active_admin()) WITH CHECK(is_active_admin());`);
  await db.exec(patch);
  const valid={name:'Test business',business_number:'123-45-67890',representative:'Test representative',contact_name:'Test contact',contact_phone:'010-0000-0000',email:'fixture@example.invalid',program_types:'Field trip',description:'Local validation only.'};
  const insert=async(extra={})=>{const data={...valid,...extra};return db.query(`INSERT INTO partner_inquiries(${Object.keys(data).join(',')}) VALUES(${Object.keys(data).map((_,i)=>'$'+(i+1)).join(',')})`,Object.values(data));};
  for(const role of ['anon','authenticated']){
   await db.exec(`SET ROLE ${role}`); await insert();
   for(const bad of [{status:'approved'},{reviewed_by:'11111111-1111-4111-8111-111111111111'},{reviewed_at:new Date().toISOString()},{memo:'Forged internal note'},{rejection_reason:'Forged rejection'},{email:'broken'},{contact_phone:'xxx'},{description:''}])
    await assert.rejects(insert(bad),e=>e.code==='42501');
   assert.equal((await db.query('SELECT * FROM partner_inquiries')).rows.length,0);
   await db.exec('RESET ROLE');
  }
  await db.exec("SET test.admin='true'; SET ROLE authenticated; UPDATE partner_inquiries SET status='approved',memo='Reviewed';");
  assert.equal((await db.query("SELECT count(*)::int AS n FROM partner_inquiries WHERE status='approved'")).rows[0].n,2);
 }finally{await db.close();}
});
