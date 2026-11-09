import test from 'node:test';
import assert from 'node:assert/strict';
import { editDocument, parseDocument, readDocument, convertDocument, formatDocument } from '../src/client/document.ts';
import { yamlKeyOffset, yamlHighlightRanges } from '../src/client/yaml.ts';
import { DocumentSession } from '../src/client/session.ts';
import { stageDraft, patchNetwork, networkDraft } from '../src/client/daily.ts';
import type { DocumentFormat } from '../src/client/types.ts';
const text = `# Kat config
schema_version: 1
client:
  mode: rule # keep mode
  http_port: 17890
kernel:
  # nodes
  outbounds:
    - name: A # A comment
      type: socks5
      server: 127.0.0.1
      port: 1234
      extra: 9007199254740993
    # B prefix
    - {name: B, type: socks5, server: 127.0.0.1, port: 2345, extra: 9007199254740992} # B comment
  providers: [{name: p, type: file, path: /loopback}] # providers
  routing:
    rules:
      - {domain: test.invalid, outbound: direct} # first
      - and: [{domain: other.invalid}, {network: tcp}]
        action: direct # second
  limits: {connections: 12, precise: 1.234567890123456789, exp: 1.2300e+12} # limits
  note: |+ # block comment
    untouched text
    # not a comment token

# footer
`;
const flow = '{schema_version: 1, client: {mode: rule}, kernel: {outbounds: [{name: A, type: socks5, server: 127.0.0.1, port: 1234, extra: 9007199254740993}, {name: B, type: socks5, server: 127.0.0.1, port: 2345}], limits: {precise: 1.234567890123456789}}} # tail\n';
const edit = (s:string, fn:(d:any)=>void) => editDocument(s,fn,'yaml');
for (const fmt of ['yaml','yml'] as const) test(`${fmt} no-op and scalar change are byte-exact`,()=>{
  assert.equal(editDocument(text,()=>{},fmt),text);
  assert.equal(editDocument(text,d=>{d.client.mode='direct';},fmt),text.replace('mode: rule','mode: direct'));
  const crlf=text.replaceAll('\n','\r\n');assert.equal(editDocument(crlf,d=>{d.client.mode='global';},fmt),crlf.replace('mode: rule','mode: global'));
});
test('block/flow edits preserve unrelated content, numbers and comments',()=>{
  for(const src of [text,flow]){
    const out=edit(src,d=>{d.kernel.outbounds[0].port=1235;});
    assert.equal(out,src.replace('port: 1234','port: 1235'));
    assert.ok(out.includes('9007199254740993'));assert.ok(out.includes('1.234567890123456789'));
  }
});
test('map add/remove, implicit null, empty collection and string type edits',()=>{
  let s=edit(text,d=>{d.client.probe_url='http://127.0.0.1/probe';d.kernel.dns={servers:['system'],cache_entries:0};});
  assert.equal(parseDocument(s,'yaml').client.probe_url,'http://127.0.0.1/probe');assert.ok(s.includes('extra: 9007199254740993'));
  s=edit(s,d=>{delete d.client.probe_url;delete d.kernel.dns.servers;});assert.equal(parseDocument(s,'yaml').kernel.dns.servers,undefined);
  s=edit(text.replace('http_port: 17890','http_port: # implicit'),d=>{d.client.http_port=18080;});assert.equal(parseDocument(s,'yaml').client.http_port,18080);assert.ok(s.includes('# implicit'));
  s=edit(text,d=>{d.kernel.providers=[];});assert.deepEqual(parseDocument(s,'yaml').kernel.providers,[]);assert.ok(s.includes('# providers'));
  for(const v of ['true','9007199254740993','a: b','x # y','line\nnext','', 'null']){s=edit(text,d=>{d.kernel.note=v;});assert.equal(parseDocument(s,'yaml').kernel.note,v);assert.ok(s.includes('# block comment'));}
});
test('block sequence append/insert/delete/reorder keeps source tokens and comments',()=>{
  for(const change of [
    (d:any)=>d.kernel.outbounds.push({name:'C',type:'socks5',server:'127.0.0.1',port:3456}),
    (d:any)=>d.kernel.outbounds.unshift({name:'C',type:'socks5',server:'127.0.0.1',port:3456}),
    (d:any)=>d.kernel.outbounds.reverse(),
    (d:any)=>d.kernel.outbounds.splice(1,1),
    (d:any)=>d.kernel.routing.rules.reverse(),
  ]){
    const out=edit(text,change);parseDocument(out,'yaml');
    assert.ok(out.includes('9007199254740993'));assert.ok(out.includes('1.234567890123456789'));assert.ok(out.includes('# B comment'));assert.ok(out.includes('# B prefix'));assert.ok(out.includes('# footer'));
  }
  const out=edit(text,d=>d.kernel.outbounds.reverse());assert.ok(out.indexOf('9007199254740992')<out.indexOf('9007199254740993'));
});
test('flow sequence/map additions/removals/reorders and trailing comma preserve legal text',()=>{
  for(const src of [flow,flow.replace('extra: 9007199254740993}', 'extra: 9007199254740993,}').replace('port: 2345}]','port: 2345},]')])for(const change of [
    (d:any)=>d.kernel.outbounds.reverse(),
    (d:any)=>d.kernel.outbounds.push({name:'C',type:'socks5',server:'127.0.0.1',port:3456}),
    (d:any)=>d.kernel.outbounds.splice(0,1),
    (d:any)=>{d.client.http_port=17890;delete d.kernel.limits.precise;},
  ]){const out=edit(src,change);parseDocument(out,'yaml');assert.ok(out.includes('# tail'));}
});
test('format and conversion retain exact numeric lexemes and YAML comments',()=>{
  const out=formatDocument(text,'yaml');assert.ok(out.includes('# A comment'));assert.ok(out.includes('# block comment'));assert.ok(out.includes('9007199254740993'));assert.ok(out.includes('1.234567890123456789'));assert.ok(out.includes('1.2300e+12'));
  const json=convertDocument(text,'yaml','json');assert.ok(json.includes('9007199254740993'));assert.ok(json.includes('1.234567890123456789'));assert.ok(!json.includes('# A comment'));assert.equal(parseDocument(json).client.mode,'rule');
  const yaml=convertDocument(json,'json','yaml');assert.ok(yaml.includes('9007199254740993'));assert.ok(yaml.includes('1.234567890123456789'));assert.equal(parseDocument(yaml,'yaml').client.mode,'rule');
  assert.equal(convertDocument(text,'yaml','yml'),text);
});
test('format selection does not bypass Kat schema; unsupported YAML rejects before mutator',()=>{
  const invalid=[
    text+'---\n{}\n',text.replace('mode: rule','mode: rule\n  mode: global'),
    text.replace('mode: rule','mode: &x rule'),text.replace('mode: rule','mode: *x'),text.replace('mode: rule','mode: !thing rule'),
    text.replace('mode: rule','mode: !!timestamp 2026-10-28'),text.replace('mode: rule','1: rule'),text.replace('mode: rule','? [mode]\n  : rule'),
    text.replace('mode: rule','<<: {}'),text.replace('mode: rule','mode: .nan'),text.replace('mode: rule','mode: .inf'),
    text.replace('  mode: rule','  mode: rule\n  extra: '+'['.repeat(66)+'0'+']'.repeat(66)),
    'proxies: []\nproxy-groups: []\nrules: []\n', '[1, 2]', 'schema_version: 1\nclient: true\nkernel: {}',
  ];
  for(const src of invalid){let called=false;assert.throws(()=>edit(src,()=>{called=true;}),src.slice(0,150));assert.equal(called,false);}
  assert.throws(()=>parseDocument('{"schema_version":1,"schema_version":1,"client":{"mode":"rule"},"kernel":{}}'));
  assert.throws(()=>parseDocument(text+'a: '+'x'.repeat(1048576),'yaml'));
});
test('prototype keys remain data and are preserved',()=>{
  const src=text+'__proto__: {safe: 9007199254740993}\nconstructor: extra\n';const d=parseDocument(src,'yaml');assert.equal(Object.hasOwn(d,'__proto__'),true);assert.equal(({} as any).safe,undefined);assert.equal(edit(src,d=>{d.client.mode='direct';}),src.replace('mode: rule','mode: direct'));
});
test('highlight and key location respect YAML strings, comments and escaped markup',()=>{
  const offset=yamlKeyOffset(text,'outbounds');assert.equal(text.slice(offset,offset+9),'outbounds');
  const h=yamlHighlightRanges(text);assert.ok(h.some(r=>r.kind==='k'&&text.slice(r.start,r.end)==='schema_version'));assert.ok(h.some(r=>r.kind==='c'&&text.slice(r.start,r.end)==='# A comment'));
  const block=h.find(r=>r.kind==='s'&&text.slice(r.start,r.end).startsWith('|+'));assert.ok(block);
});
function session(format:DocumentFormat='yaml'){
  const calls:any[]=[];
  const s=new DocumentSession({validate:async(text,format)=>{calls.push(['validate',format]);},apply:async(text,format)=>{calls.push(['apply',format]);return {text,format,path:'kat-client.'+format};}});
  s.load({text,format,path:'kat-client.'+format});return {s,calls};
}
test('session always sends format and tracks saved/draft formats independently',async()=>{
  const {s,calls}=session();s.setDraft(text,'yml');assert.equal(s.dirty,true);assert.equal(s.savedFormat,'yaml');await s.save();assert.deepEqual(calls,[['validate','yml'],['apply','yml']]);assert.equal(s.savedFormat,'yml');assert.equal(s.path,'kat-client.yml');assert.equal(s.dirty,false);
  s.setDraft(text,'yaml');s.cancel();assert.equal(s.draftFormat,'yml');
});
test('YAML visual saves use accepted CST source; raw saved changes feed all forms',async()=>{
  const {s,calls}=session();await s.edit(d=>{d.client.mode='direct';});assert.equal(s.saved,text.replace('mode: rule','mode: direct'));assert.deepEqual(calls,[['validate','yaml'],['apply','yaml']]);
  s.setDraft(s.draft.replace('http_port: 17890','http_port: 18080'));await s.save();assert.equal(networkDraft(s.source!).http_port,'18080');
  const draft=networkDraft(s.source!);draft.http_port='18081';await s.edit(d=>patchNetwork(d,draft,new Set(['http_port'])));assert.ok(s.saved!.includes('9007199254740993'));
});
test('validate/apply failure preserves exact format draft, accepted source and path',async()=>{
  for(const failure of ['validate','apply']){
    const s=new DocumentSession({validate:async()=>{if(failure==='validate')throw Error('failed');},apply:async()=>{throw Error('failed');}});s.load({text,format:'yaml',path:'kat-client.yaml'});
    const json=convertDocument(text,'yaml','json');s.setDraft(json,'json');await assert.rejects(s.save());assert.equal(s.draft,json);assert.equal(s.draftFormat,'json');assert.equal(s.savedFormat,'yaml');assert.equal(s.path,'kat-client.yaml');assert.equal(s.saved,text);
  }
});
test('typing, undo and format-only changes during save survive accepted reply',async()=>{
  for(const concurrent of [(s:DocumentSession)=>s.setDraft(s.draft,'yml'),(s:DocumentSession)=>{s.setDraft('typing','yaml');s.setDraft(text,'yaml');}]){
    let reply!:(r:any)=>void;const s=new DocumentSession({validate:async()=>{},apply:()=>new Promise(r=>reply=r)});s.load({text,format:'yaml',path:'kat-client.yaml'});
    const pending=s.edit(d=>{d.client.mode='direct';});await new Promise(r=>setTimeout(r,0));concurrent(s);const draft=s.draft,format=s.draftFormat;reply({text:text.replace('mode: rule','mode: direct'),format:'yaml',path:'kat-client.yaml'});await pending;
    assert.equal(s.draft,draft);assert.equal(s.draftFormat,format);assert.equal(s.source!.client.mode,'direct');assert.equal(s.dirty,true);
  }
});
test('import/backup stages exact host format without apply, including invalid drafts',async()=>{
  const {s,calls}=session();const imported='# invalid yml\nclient: [';
  await stageDraft(s,async()=>({text:imported,format:'yml'}),async()=>true);assert.equal(s.draft,imported);assert.equal(s.draftFormat,'yml');assert.equal(s.saved,text);assert.deepEqual(calls,[]);s.cancel();assert.equal(s.draftFormat,'yaml');
  const json=convertDocument(text,'yaml','json');await stageDraft(s,async()=>({text:json}),async()=>true);assert.equal(s.draftFormat,'json');
});
test('format-only edits and typing during file replacement confirmation are protected',async()=>{
  const {s}=session();let result!:(r:any)=>void;const pending=stageDraft(s,()=>new Promise(r=>result=r),async()=>false);s.setDraft(text,'yml');result({text,format:'yaml'});assert.equal(await pending,false);assert.equal(s.draftFormat,'yml');
  let answer!:(r:boolean)=>void;const confirmPending=stageDraft(s,async()=>({text:'replace',format:'json'}),()=>new Promise(r=>answer=r));s.setDraft('more typing','yml');answer(true);assert.equal(await confirmPending,false);assert.equal(s.draft,'more typing');
});

test('yaml.v3-compatible numeric spellings and timestamps',()=>{
  const src=text+"octal: 0777\nbinary: 0b11\nhex: 0x10\nmodern: 0o17\nseparator: 1_234\nfraction: +.5000000000000000000001\nexp: 1.e+12\n";
  const d=readDocument(src,'yaml');assert.equal(d.octal,511);assert.equal(d.binary,3);assert.equal(d.separator,1234);
  const json=convertDocument(src,'yaml','json');assert.ok(json.includes('"octal": 511'));assert.ok(json.includes('"binary": 3'));assert.ok(json.includes('0.5000000000000000000001'));assert.ok(json.includes('1.0e+12'));
  assert.equal(edit(src,d=>{d.client.mode='direct';}),src.replace('mode: rule','mode: direct'));
  assert.ok(formatDocument(src,'yaml').includes('0777'));
  for(const v of ['2026-10-28','2026-1-2T15:4:5Z','!!bool yes','!!int eight','!!null wrong'])assert.throws(()=>readDocument(text+'extra: '+v+'\n','yaml'));
});

test('replacement plus move does not steal an existing large-number CST',()=>{
  const out=edit(text,d=>{d.kernel.outbounds=[{name:'C',type:'socks5',server:'127.0.0.1',port:3456},d.kernel.outbounds[0]];});
  const start=out.indexOf('name: A');assert.ok(start>=0);assert.ok(out.slice(start).includes('extra: 9007199254740993'));
});

test('JSON enormous unchanged tokens remain legal; YAML overflowing implicit decimal is a string as in yaml.v3',()=>{
  const json='{"schema_version":1,"client":{"mode":"rule","future":1e999},"kernel":{}}';
  assert.equal(editDocument(json,d=>{d.client.mode='direct';}),json.replace('"rule"','"direct"'));
  const yaml=text+'future: 1e999\n';assert.equal(readDocument(yaml,'yaml').future,'1e999');assert.equal(edit(yaml,d=>{d.client.mode='direct';}),yaml.replace('mode: rule','mode: direct'));
});

test('integer-like string mapping keys keep their source order after edits',()=>{
  const src=text+"future: {'2': 9007199254740993, '1': before}\n";
  assert.equal(edit(src,d=>{d.future['1']='after';}),src.replace("'1': before","'1': after"));
});

test('signed octal and overflowing based tokens keep yaml.v3 scalar types in conversion',()=>{
  const src=text+'negative: -0o17\npositive: +0o17\nhex_string: 0x10000000000000000\nbinary_string: 0b1'+'0'.repeat(64)+'\nlegacy_float: 07777777777777777777777777777777\n';
  const d=readDocument(src,'yaml');assert.equal(d.negative,-15);assert.equal(d.positive,15);assert.equal(d.hex_string,'0x10000000000000000');assert.equal(typeof d.binary_string,'string');
  const json=convertDocument(src,'yaml','json');assert.ok(json.includes('"negative": -15'));assert.ok(json.includes('"hex_string": "0x10000000000000000"'));assert.ok(json.includes('"legacy_float": 7777777777777777777777777777777'));
});
