import {PGlite} from '@electric-sql/pglite';
import {pgcrypto} from '@electric-sql/pglite/contrib/pgcrypto';
import {readFileSync} from 'node:fs';
export const snapshots=JSON.parse(readFileSync(new URL('./rpc-review-fixture.json',import.meta.url),'utf8'));
export const id=n=>`${String(n).padStart(8,'0')}-1111-4111-8111-111111111111`;
export async function as(db,role,user=''){
 await db.exec('RESET ROLE');
 await db.query("SELECT set_config('request.jwt.claims',$1,false)",[JSON.stringify({role,sub:user})]);
 await db.exec(`SET ROLE ${role}`);
}
export async function fixture(env){
 const db=new PGlite({extensions:{pgcrypto}});
 await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS; CREATE ROLE damda_payment_code;
 CREATE SCHEMA auth; CREATE SCHEMA extensions; CREATE SCHEMA payment_private;
 CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
 GRANT USAGE ON SCHEMA public,auth,extensions TO anon,authenticated,service_role,damda_payment_code;
 CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql AS $$SELECT nullif(current_setting('request.jwt.claims',true)::jsonb->>'sub','')::uuid$$;
 CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql AS $$SELECT current_setting('request.jwt.claims',true)::jsonb->>'role'$$;
 CREATE TABLE auth.users(id uuid PRIMARY KEY);
 SET check_function_bodies=false;`);
 const enums=new Map();
 for(const e of snapshots[env].enums||[]){if(!enums.has(e.name))enums.set(e.name,[]);enums.get(e.name).push(e);}
 for(const [name,values] of enums)await db.exec(`CREATE TYPE public."${name}" AS ENUM (${values.sort((a,b)=>a.sort-b.sort).map(e=>"'"+e.label.replaceAll("'","''")+"'").join(',')})`);
 const tables=new Map();
 for(const c of snapshots[env].columns){if(!tables.has(c.table))tables.set(c.table,[]);tables.get(c.table).push(c);}
 for(const [table,cols] of tables){
  await db.exec(`CREATE TABLE public."${table}" (${cols.map(c=>`"${c.column}" ${c.type}`).join(',')})`);
  if(cols.some(c=>c.column==='id'&&c.type==='uuid')) await db.exec(`ALTER TABLE public."${table}" ALTER COLUMN id SET DEFAULT gen_random_uuid()`);
  for(const name of ['created_at','updated_at'])if(cols.some(c=>c.column===name))await db.exec(`ALTER TABLE public."${table}" ALTER COLUMN ${name} SET DEFAULT now()`);
 }
 await db.exec(`ALTER TABLE user_roles ADD PRIMARY KEY(id);
 ALTER TABLE site_daily_metrics ADD UNIQUE(metric_date,metric_key);
 ALTER TABLE site_daily_visitors ADD UNIQUE(metric_date,visitor_hash);
 ALTER TABLE product_preview_tokens ALTER COLUMN token SET DEFAULT gen_random_uuid();
 ALTER TABLE product_preview_tokens ALTER COLUMN expires_at SET DEFAULT now()+interval '1 day';
 CREATE FUNCTION payment_private.jwt_uid() RETURNS uuid LANGUAGE sql AS $$SELECT auth.uid()$$;
 CREATE FUNCTION payment_private.jwt_role() RETURNS text LANGUAGE sql AS $$SELECT auth.role()$$;
 CREATE FUNCTION public.assert_payment_boundary() RETURNS void LANGUAGE sql AS $$SELECT$$;
 CREATE TABLE payment_private.configuration(boundary_activated boolean,approvals_enabled boolean);
 INSERT INTO payment_private.configuration VALUES(true,true);`);
 for(const f of snapshots[env].functions){
  await db.exec(f.definition);
  await db.exec(`REVOKE EXECUTE ON FUNCTION public.${f.identity} FROM PUBLIC;
   GRANT EXECUTE ON FUNCTION public.${f.identity} TO service_role${f.anon?',anon':''}${f.member?',authenticated':''};`);
 }
 await db.exec(`INSERT INTO user_roles(id,role) VALUES('${id(1)}','daycare'),('${id(2)}','daycare'),('${id(3)}','daycare'),('${id(4)}','business_owner'),('${id(5)}','business_owner');
 INSERT INTO daycares(id,status,deleted_at,name,email,contact_phone) VALUES
 ('${id(1)}','approved',NULL,'Approved fixture','approved@example.invalid','01011112222'),
 ('${id(2)}','pending',NULL,'Pending fixture','pending@example.invalid','01022223333'),
 ('${id(3)}','rejected',NULL,'Revoked fixture','revoked@example.invalid','01033334444'),
 ('${id(8)}','deleted',now(),'Deleted fixture','deleted@example.invalid','01088889999');
 INSERT INTO admins(id,is_active,password_hash) VALUES('${id(6)}',true,encode(extensions.digest('OldPassword!123'||'damda-salt-2024','sha256'),'hex')),('${id(7)}',false,'inactive');
 INSERT INTO business_owners(id,auth_user_id,status,name,email) VALUES('${id(40)}','${id(4)}','active','Owner fixture','owner@example.invalid'),('${id(50)}','${id(5)}','inactive','Inactive owner','inactive@example.invalid');
 INSERT INTO businesses(id,business_owner_id,name,status,is_primary,is_visible,business_number,email,contact_name) VALUES('${id(20)}','${id(40)}','Visible business','active',false,true,'PRIVATE_NUMBER','private@example.invalid','PRIVATE_CONTACT');
 INSERT INTO products(id,business_id,business_owner_id,name,is_visible,is_sold_out,original_price,sale_price,min_participants,max_participants,view_count,display_order) VALUES('${id(10)}','${id(20)}','${id(40)}','Visible experience',true,false,2000,1000,1,20,3,1),('${id(11)}','${id(20)}','${id(40)}','Hidden experience',false,false,2000,1000,1,20,0,2);
 INSERT INTO product_preview_tokens(product_id,business_owner_id,token,expires_at) VALUES('${id(10)}','${id(40)}','${id(30)}',now()+interval '1 day'),('${id(10)}','${id(40)}','${id(31)}',now()-interval '1 day');
 INSERT INTO reservations(id,product_id,daycare_id,reserved_date,status) VALUES('${id(60)}','${id(10)}','${id(3)}',current_date+10,'confirmed');
 INSERT INTO reservation_holds(id,product_id,daycare_id,reserved_date,expires_at) VALUES('${id(61)}','${id(10)}','${id(1)}',current_date+11,now()-interval '1 hour'),('${id(62)}','${id(10)}','${id(3)}',current_date+12,now()-interval '1 hour');`);
 return db;
}
