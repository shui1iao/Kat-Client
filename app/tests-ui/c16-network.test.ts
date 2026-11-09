import test from 'node:test';
import assert from 'node:assert/strict';
import {dnsPolicies,patchDNSPolicies,reorderDNSPolicy,validHostAddress,dnsDomainError} from '../src/client/dnsPolicy.ts';
import {parseDocument,editDocument,convertDocument} from '../src/client/document.ts';
const text=` {"schema_version":1,"client":{"mode":"rule","ipv6":false},"kernel":{"dns":{"server":"system","nameserver-policy":{"+.example.com":["1.1.1.1","8.8.8.8"],"exact.test":"9.9.9.9","internal.test":"1.0.0.1"},"hosts":{"*.local.test":["192.0.2.1","2001:db8::1"]}},"untouched":9007199254740993}}\n`;
test('IPv6 patch is target-only, preserving DNS source and large integers',()=>{
 const next=editDocument(text,d=>{d.client.ipv6=true});assert.equal(next,text.replace('"ipv6":false','"ipv6":true'));
});
test('mihomo policy import preserves order and scalar/list servers; edits only patch DNS rules',()=>{
 const d=parseDocument(text),rules=dnsPolicies(d);assert.deepEqual(rules.map(r=>r.match),['domain_suffix','domain','domain']);assert.deepEqual(rules[0].servers,['1.1.1.1','8.8.8.8']);assert.deepEqual(rules[1].servers,['9.9.9.9']);
 const reordered=reorderDNSPolicy(rules,2,0);assert.equal(reordered[0].domain,'internal.test');const next=editDocument(text,d=>patchDNSPolicies(d,reordered));const after=parseDocument(next);assert.equal(after.kernel.dns['nameserver-policy'],undefined);assert.equal(after.kernel.dns.rules[0].match,'domain');assert.deepEqual(after.kernel.dns.hosts,d.kernel.dns.hosts);assert.ok(next.includes('9007199254740993'));
});
test('native keyword rules survive JSON↔YAML round-trips without mihomo conversion or error',()=>{
 const original=editDocument(text,d=>patchDNSPolicies(d,[
  {match:'domain_suffix',domain:'example.com',servers:['1.1.1.1','8.8.8.8']},
  {match:'keyword',domain:'internal',servers:['9.9.9.9','tcp://1.0.0.1:53']},
  {match:'domain',domain:'exact.test',servers:['8.8.4.4']}
 ]));
 const want=parseDocument(original).kernel.dns;
 const yaml=convertDocument(original,'json','yaml'),json=convertDocument(yaml,'yaml','json'),again=convertDocument(json,'json','yaml');
 for(const [source,format] of [[original,'json'],[yaml,'yaml'],[json,'json'],[again,'yaml']] as const){
  const d=parseDocument(source,format);assert.deepEqual(d.kernel.dns,want);assert.equal(d.kernel.dns['nameserver-policy'],undefined);assert.equal(d.kernel.dns.rules[1].match,'keyword');assert.ok(source.includes('9007199254740993'));
 }
});
test('non-keyword JSON/YAML exports retain each source DNS representation',()=>{
 const native=editDocument(text,d=>patchDNSPolicies(d,dnsPolicies(d)));
 for(const original of [text,native]){
  const want=parseDocument(original).kernel.dns;
  const yaml=convertDocument(original,'json','yaml'),json=convertDocument(yaml,'yaml','json');
  assert.deepEqual(parseDocument(yaml,'yaml').kernel.dns,want);assert.deepEqual(parseDocument(json).kernel.dns,want);
  assert.deepEqual(Object.keys(parseDocument(json).kernel.dns),Object.keys(want));
  if(want['nameserver-policy'])assert.deepEqual(Object.keys(parseDocument(json).kernel.dns['nameserver-policy']),Object.keys(want['nameserver-policy']));
 }
});
test('Hosts input supports wildcard and multiple address families',()=>{
 for(const ip of ['192.0.2.1','2001:db8::1','::ffff:192.0.2.1'])assert.equal(validHostAddress(ip),true,ip);
 for(const ip of ['256.1.1.1','01.2.3.4','example.com','2001:gg::1','fe80::1%eth0'])assert.equal(validHostAddress(ip),false,ip);
 assert.equal(dnsDomainError('*.example.com',true),'');assert.notEqual(dnsDomainError('**.example.com',true),'');
});
