import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('candidate16 production core version is injected from existing CLI authority, never a UI fixture',()=>{
 const core=readFileSync(new URL('../../core/cmd/kat/main.go',import.meta.url),'utf8');
 const version=/^const version = "([0-9]+\.[0-9]+\.[0-9]+)"$/m.exec(core)?.[1];assert.ok(version);
 const script=readFileSync(new URL('../../deliverables/scripts/build-flow-production.sh',import.meta.url),'utf8');
 assert.match(script,/core\/cmd\/kat\/main.go/);assert.match(script,/kernel\.Version=\$VERSION/);
 assert.match(script,/CORE-FLOW-BUILD\.json/);assert.match(script,/'version':version/);
});
test('merged diagnostic routing display reuses log ConnectionRule and keeps distinct policy chain',()=>{
 const ui=readFileSync(new URL('../src/components/NetworkDiagnostics.tsx',import.meta.url),'utf8');
 assert.match(ui,/import \{ConnectionRule\} from '\.\/labels'/);assert.match(ui,/<th>规则<\/th><th>策略链<\/th>/);
 assert.match(ui,/<ConnectionRule raw=\{x\.rule/);assert.doesNotMatch(ui,/规则 → 策略链/);
});
