import test from 'node:test';
import assert from 'node:assert/strict';
import { errorText, errorLocation } from '../src/lib/errors';

test('host/core errors have Chinese main text, unchanged diagnostic code and safe field location',()=>{
 const text=errorText({code:'PIPE_IO',message:'Operating system operation failed https://user:pass@example.invalid/a?token=private',path:'C:\\Users\\private\\secret'});
 assert.match(text,/无法与网络服务通信/);assert.match(text,/诊断码：PIPE_IO/);assert.doesNotMatch(text,/Operating|private|example|Users/);assert.doesNotMatch(text,/管理员|重装/);
 assert.match(errorText({code:'DOCUMENT_INVALID',message:'invalid type',path:'kernel.outbounds[2].port'}),/字段 kernel.outbounds\[2\].port/);
 assert.match(errorText({code:'FUTURE_BACKEND_CODE',message:'https://username:password@private.invalid/token'}),/^操作未完成.*FUTURE_BACKEND_CODE/);
});
test('unknown English, JSON objects and credential-bearing messages never echo raw details',()=>{
 for(const e of ['Something broke at https://user:pass@secret.invalid/?token=secret','Unexpected token "MY_SECRET" at position 19',new Error('password=MY_SECRET'),'{"code":"PIPE_IO","message":"Bearer MY_SECRET","path":"/root/private"}',{reason:'unsupported plugin https://private.invalid/MY_SECRET'},{message:'Oops',code:'https://private.invalid/MY_SECRET'}]){
  const text=errorText(e);assert.match(text,/[\u3400-\u9fff]/);assert.doesNotMatch(text,/MY_SECRET|secret\.invalid|private\.invalid|\/root|Something|Oops|Bearer/);
 }
 assert.equal(errorText(null),'');assert.equal(errorText(''),'');
});
test('JSON/YAML parser text is localized but line/column/offset survive without source excerpts',()=>{
 const y=Object.assign(new Error('Map keys must be unique at line 3, column 2:\n token: MY_SECRET'),{code:'DUPLICATE_KEY',linePos:[{line:3,col:2}]});
 assert.equal(errorText(y),'YAML 配置含重复键 · 第 3 行，第 2 列（诊断码：DUPLICATE_KEY）');
 const j=new Error('JSON 语法错误 · Unexpected token MY_SECRET in JSON at position 4');
 assert.deepEqual(errorLocation(j,'{\n  @'),{line:2,column:3,position:4});assert.match(errorText(j,'{\n  @'),/第 2 行，第 3 列/);assert.doesNotMatch(errorText(j),/MY_SECRET|Unexpected/);
 assert.match(errorText(new Error('YAML 不支持 anchors / aliases (line 4)')),/YAML 不支持 锚点或别名 · 第 4 行/);
});
test('established local validation/attention survives, rendering twice keeps codes and fields',()=>{
 for(const msg of ['名称重复','原文有未保存草稿','保存失败 · 草稿已保留','DNS 缓存条数须为 0–4096 的整数','仍有 2 处引用：document.kernel.routing.final'])assert.equal(errorText(msg),msg);
 const once=errorText({code:'INVALID_PARAMS',path:'client.http_port',message:'bad value'});assert.equal(errorText(once),once);
 const t=errorText('配置错误 password="MY_SECRET" token=MY_SECRET https://private.invalid/MY_SECRET');assert.doesNotMatch(t,/MY_SECRET|private\.invalid/);
});

test('installed-service relaunch instruction is precise and never suggests admin GUI or reinstall',()=>{
 const t=errorText({code:'INSTALL_RELAUNCH_REQUIRED',message:'old location https://private.invalid/SECRET'});
 assert.equal(t,'服务已安装，请退出后从已安装目录启动 Kat（诊断码：INSTALL_RELAUNCH_REQUIRED）');
 assert.doesNotMatch(t,/管理员|重装|重复安装|private|SECRET/);
});


test('frozen cancellation, uncertain mutation and interface identity codes render exact Chinese in every supported representation',()=>{
 for(const [code,message] of Object.entries({request_canceled:'请求已取消，未接纳更改',CORE_MUTATION_UNCERTAIN:'内核变更结果尚未确认，请等待状态核对，暂勿重复保存或切换网络',INTERFACE_IDENTITY:'无法确认网络接口身份，恢复尚未完成，请查看诊断记录'})){
  const unsafe='unsafe https://fake:private@private.example.invalid/?token=FAKE_SECRET password=FAKE_SECRET';
  for(const value of [code,code+': '+unsafe,new Error(code+': '+unsafe),{code,message:unsafe},JSON.stringify({code,message:unsafe})]){
   const text=errorText(value);assert.equal(text,message+'（诊断码：'+code+'）');assert.equal(errorText(text),text);assert.equal(errorText(errorText(text)),text);assert.doesNotMatch(text,/FAKE_SECRET|private\.example|unsafe|password=/);
  }
 }
});

test('only exact frozen Go lowercase codes are accepted, never arbitrary lowercase native text',()=>{
 for(const code of ['request_cancelled','request_canceled_extra','core_mutation_uncertain','interface_identity','future_native_error']){
  const message='opaque FAKE_SECRET https://private.example.invalid/?token=FAKE_SECRET';
  for(const value of [code,{code,message},JSON.stringify({code,message})])assert.equal(errorText(value),'操作未完成，请查看诊断记录');
 }
 assert.match(errorText('import_failed'),/^无法解析导入内容.*诊断码：import_failed/);
});
