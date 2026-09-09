import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fixture,as,id,snapshots} from './rpc-review-fixture.mjs';
const patch=env=>readFileSync(new URL(`../../operations/20260909_rpc_review_${env}.sql`,import.meta.url),'utf8');
for(const env of ['dev','prod']){
 test(`${env}: reproduce reviewed gaps with original definitions`,async()=>{
  const db=await fixture(env);try{
   await as(db,'authenticated',id(2));
   assert.equal((await db.query(`SELECT array_length(get_unavailable_dates('${id(10)}'),1) AS n`)).rows[0].n,1);
   await as(db,'authenticated',id(5));assert.equal((await db.query('SELECT is_business_owner() AS ok')).rows[0].ok,true);
   await as(db,'authenticated',id(6));assert.equal((await db.query("SELECT change_admin_password(NULL,'NewPassword!123') AS ok")).rows[0].ok,true);
   await as(db,'anon');const preview=(await db.query(`SELECT get_business_product_preview('${id(20)}','${id(10)}','${id(30)}') AS data`)).rows[0].data;
   assert.equal(preview.business.business_number,'PRIVATE_NUMBER');
  }finally{await db.close();}
 });
 test(`${env}: all retained RPC authorization and output matrix`,async()=>{
  const db=await fixture(env);try{
   await db.exec(patch(env));
   const adminCalls=[
    `approve_business_owner_signup('${id(99)}','${id(40)}')`, `approve_partner_onboarding('${id(99)}')`,
    `review_business_owner_signup('${id(99)}','approved',NULL,NULL)`, `create_admin_product_preview_token('${id(99)}')`,
    `delete_business_owner_safely('${id(99)}','fixture')`, `delete_daycare_safely('${id(99)}','fixture')`,
    `change_admin_password('wrong','NewPassword!123')`, `get_site_analytics(current_date,current_date)`];
   for(const user of [id(1),id(2),id(3),id(4),id(5),id(7)]){
    await as(db,'authenticated',user);
    for(const call of adminCalls)await assert.rejects(db.query('SELECT '+call),e=>/ADMIN_REQUIRED|ADMIN_NOT_FOUND|관리자만/.test(e.message));
   }
   for(const user of [id(2),id(3),id(5)]){
    await as(db,'authenticated',user);
    for(const call of [`get_unavailable_dates('${id(10)}')`,`check_reservation_available('${id(10)}',current_date)`,`cleanup_expired_holds()`])await assert.rejects(db.query('SELECT '+call),e=>e.code==='42501');
    if(env==='dev')await assert.rejects(db.query(`SELECT get_product_remaining('${id(10)}',current_date)`),e=>e.code==='42501');
   }
   await as(db,'authenticated',id(1));
   assert.equal((await db.query('SELECT is_daycare() AS ok')).rows[0].ok,true);
   assert.equal((await db.query('SELECT get_user_role() AS role')).rows[0].role,'daycare');
   assert.equal((await db.query(`SELECT (check_reservation_available('${id(10)}',current_date+10)->>'available')::boolean AS ok`)).rows[0].ok,false);
   assert.equal((await db.query(`SELECT (check_reservation_available('${id(10)}',current_date+20)->>'available')::boolean AS ok`)).rows[0].ok,true);
   await as(db,'postgres');
   await db.exec(`INSERT INTO reservation_holds(id,product_id,daycare_id,reserved_date,expires_at) VALUES('${id(63)}','${id(10)}','${id(3)}',current_date+13,now()+interval '1 hour')`);
   await as(db,'authenticated',id(1));await db.exec('SELECT cleanup_expired_holds()');
   await as(db,'postgres');assert.equal((await db.query(`SELECT count(*)::int AS n FROM reservation_holds WHERE id='${id(62)}'`)).rows[0].n,0);
   assert.equal((await db.query(`SELECT count(*)::int AS n FROM reservation_holds WHERE id='${id(63)}'`)).rows[0].n,1);
   if(env==='dev'){
    await db.exec(`INSERT INTO product_schedules(product_id,capacity,slot_time,is_active,day_of_week) VALUES('${id(10)}',10,NULL,true,NULL)`);
    await as(db,'authenticated',id(1));assert.equal((await db.query(`SELECT get_product_remaining('${id(10)}',current_date) AS n`)).rows[0].n,10);
   }
   await as(db,'authenticated',id(4));
   assert.equal((await db.query('SELECT is_business_owner() AS ok')).rows[0].ok,true);
   assert.equal((await db.query('SELECT current_business_owner_id() AS owner')).rows[0].owner,id(40));
   assert.equal((await db.query(`SELECT is_current_business_owner('${id(50)}') AS ok`)).rows[0].ok,false);
   await db.exec(`SELECT get_unavailable_dates('${id(10)}')`);
   await assert.rejects(db.query(`SELECT get_unavailable_dates('${id(99)}')`),e=>e.code==='42501');
   await as(db,'authenticated',id(5));assert.equal((await db.query('SELECT is_business_owner() AS ok')).rows[0].ok,false);
   await as(db,'authenticated',id(6));
   for(const val of ['NULL',"''","'wrong'"])await assert.rejects(db.query(`SELECT change_admin_password(${val},'NewPassword!123')`),/CURRENT_PASSWORD/);
   await assert.rejects(db.query("SELECT change_admin_password('OldPassword!123',NULL)"),/PASSWORD_POLICY/);
   assert.equal((await db.query("SELECT change_admin_password('OldPassword!123','NewPassword!123') AS ok")).rows[0].ok,true);
   assert.equal((await db.query('SELECT count(*)::int AS n FROM get_site_analytics(current_date,current_date)')).rows[0].n,1);
   assert.equal((await db.query(`SELECT count(*)::int AS n FROM create_admin_product_preview_token('${id(10)}')`)).rows[0].n,1);
   await assert.rejects(db.query(`SELECT approve_business_owner_signup('${id(99)}','${id(40)}')`),/BUSINESS_SIGNUP_REQUEST_NOT_FOUND/);
   await assert.rejects(db.query(`SELECT approve_partner_onboarding('${id(99)}')`),/입점 신청을 찾을 수 없습니다/);
   await assert.rejects(db.query(`SELECT review_business_owner_signup('${id(99)}',NULL,NULL,NULL)`),/INVALID_BUSINESS_SIGNUP_STATUS/);
   await assert.rejects(db.query(`SELECT delete_business_owner_safely('${id(99)}','fixture')`),/BUSINESS_OWNER_NOT_FOUND/);
   await assert.rejects(db.query(`SELECT delete_daycare_safely('${id(99)}','fixture')`),/DAYCARE_NOT_FOUND/);
   await as(db,'authenticated',id(1));await assert.rejects(db.query(`SELECT delete_business_safely('${id(20)}','Visible business')`),/BUSINESS_ACCESS_DENIED/);
   await as(db,'anon');
   for(const f of snapshots[env].functions.filter(f=>!f.anon))assert.equal((await db.query('SELECT has_function_privilege(current_user,$1,\'EXECUTE\') AS ok',['public.'+f.identity])).rows[0].ok,false);
   assert.equal((await db.query('SELECT is_active_admin() AS a,is_daycare() AS d,is_business_owner() AS b,current_business_owner_id() AS o,get_user_role() AS r')).rows[0].a,false);
   for(const tok of [id(31),id(99)]){
    assert.equal((await db.query(`SELECT validate_product_preview_token('${id(10)}','${tok}') AS ok`)).rows[0].ok,false);
    assert.equal((await db.query(`SELECT get_product_preview('${id(10)}','${tok}') AS data`)).rows[0].data,null);
    assert.equal((await db.query(`SELECT get_business_product_preview('${id(20)}','${id(10)}','${tok}') AS data`)).rows[0].data,null);
   }
   assert.equal((await db.query(`SELECT get_business_product_preview('${id(99)}','${id(10)}','${id(30)}') AS data`)).rows[0].data,null);
   assert.equal((await db.query(`SELECT get_product_preview('${id(11)}','${id(30)}') AS data`)).rows[0].data,null);
   const preview=(await db.query(`SELECT get_business_product_preview('${id(20)}','${id(10)}','${id(30)}') AS data`)).rows[0].data;
   assert.equal(preview.business.name,'Visible business');assert.equal(preview.products.length,1);
   for(const field of ['business_number','email','representative','contact_name','contact_phone'])assert.equal(Object.hasOwn(preview.business,field),false);
   assert.equal((await db.query(`SELECT get_product_preview('${id(10)}','${id(30)}')->>'name' AS name`)).rows[0].name,'Visible experience');
   assert.equal((await db.query("SELECT find_masked_daycare_email('Approved fixture','010-1111-2222') AS email")).rows[0].email,'ap******@example.invalid');
   assert.equal((await db.query("SELECT find_masked_daycare_email('Deleted fixture','01088889999') AS email")).rows[0].email,null);
   await assert.rejects(db.query('SELECT track_site_analytics(NULL,NULL)'),/INVALID_ANALYTICS_METRIC/);
   await db.exec(`SELECT track_site_analytics('daily_visit','${id(90)}'); SELECT track_site_analytics('daily_visit','${id(90)}')`);
   if(env==='prod'){const rows=(await db.query('SELECT * FROM get_public_popular_businesses(99999)')).rows;assert.equal(rows.length,1);assert.equal(Object.hasOwn(rows[0],'email'),false);}
   await as(db,'authenticated','');await assert.rejects(db.query("SELECT create_verified_payment_order('[]','{}','card')"),e=>e.code==='42501');
   await as(db,'postgres');
   assert.equal((await db.query("SELECT metric_count FROM site_daily_metrics WHERE metric_key='daily_visit'")).rows[0].metric_count,1);
   await db.exec(`UPDATE products SET business_owner_id='${id(50)}' WHERE id='${id(10)}'`);
   await as(db,'anon');assert.equal((await db.query(`SELECT validate_product_preview_token('${id(10)}','${id(30)}') AS ok`)).rows[0].ok,false);
   assert.equal((await db.query(`SELECT get_product_preview('${id(10)}','${id(30)}') AS data`)).rows[0].data,null);
   assert.equal((await db.query(`SELECT get_business_product_preview('${id(20)}','${id(10)}','${id(30)}') AS data`)).rows[0].data,null);
  }finally{await db.close();}
 });
}
