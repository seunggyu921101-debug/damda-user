import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source=readFileSync(new URL('../src/lib/supabase/middleware.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
function middleware({user=true,status='approved',deleted_at=null,preview=false,queryError=false}={}) {
  const client={
    auth:{getUser:async()=>({data:{user:user?{id:'local-user'}:null}})},
    rpc:async()=>({data:preview,error:null}),
    from:()=>({select:()=>({eq:()=>({single:async()=>({data:queryError?null:{status,deleted_at},error:queryError?new Error('offline'):null})})})}),
  };
  const response=(kind,options)=>({kind,options,headers:new Headers(),cookies:{set(){}}});
  const modules={
    '@supabase/ssr':{createServerClient:()=>client},
    'next/server':{NextResponse:{next:options=>response('next',options),redirect:url=>response('redirect',String(url))}},
  };
  const exports={};
  new Function('require','exports',compiled)(name=>{assert.ok(modules[name],name);return modules[name];},exports);
  return path=>{
    const url=new URL(path,'https://local.example.test');
    return exports.updateSession({url:String(url),nextUrl:url,cookies:{getAll:()=>[],set(){}}});
  };
}
const privatePaths=['/home','/products','/products/12345678-1234-4234-8234-123456789012','/businesses','/businesses/12345678-1234-4234-8234-123456789012','/cart','/mypage','/mypage/reservations','/checkout','/checkout/callback'];
test('every member route accepts approved accounts and redirects each unapproved state',async()=>{
  for (const path of privatePaths) {
    assert.equal((await middleware()(path)).kind,'next',path);
    for (const [status,destination] of [['pending','complete'],['requested','complete'],['revision_required','revision'],['rejected','rejected'],['deleted','complete']]) {
      const result=await middleware({status})(path);
      assert.equal(result.kind,'redirect',`${path}: ${status}`);
      assert.equal(new URL(result.options).pathname,`/signup/${destination}`);
    }
    assert.equal((await middleware({deleted_at:'2026-09-09'})(path)).kind,'redirect');
    assert.equal((await middleware({queryError:true})(path)).kind,'redirect');
    assert.equal(new URL((await middleware({user:false})(path)).options).pathname,'/login');
  }
});
test('signup/revision/public pages, payment callbacks and validated previews remain separate',async()=>{
  for (const path of ['/','/signup/complete','/signup/revision','/signup/rejected','/privacy','/terms','/partner','/api/payment/callback','/api/payment/webhook']) {
    assert.equal((await middleware({user:false})(path)).kind,'next',path);
    assert.equal((await middleware({status:'pending'})(path)).kind,'next',path);
  }
  const path='/products/12345678-1234-4234-8234-123456789012?preview_token=local-token';
  const allowed=await middleware({user:false,preview:true})(path);
  assert.equal(allowed.kind,'next');
  assert.equal(allowed.options.request.headers.get('x-preview-mode'),'true');
  assert.equal((await middleware({status:'pending',preview:false})(path)).kind,'redirect');
});
