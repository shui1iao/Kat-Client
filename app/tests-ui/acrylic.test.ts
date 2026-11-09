import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const base = 'dccfb157695e297aaf422014c4ea1c9868afe9e2';
const read = (p:string) => readFileSync(new URL('../'+p, import.meta.url), 'utf8');
const old = (p:string) => execFileSync('git', ['show', `${base}:app/${p}`], {encoding:'utf8'});
test('native selector is Acrylic, positively verified DWM transient backdrop, never a CSS imitation', () => {
 const s=read('src-tauri/src/acrylic.rs'),css=read('src/acrylic.css');
 assert.match(s,/effects: vec!\[Effect::Acrylic\]/);
 assert.match(s,/DWMSBT_TRANSIENTWINDOW: i32 = 3/);
 assert.match(s,/&& set_attribute\(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_TRANSIENTWINDOW\)/);
 assert.match(s,/&& backdrop\(hwnd\) == Some\(DWMSBT_TRANSIENTWINDOW\)/);
 assert.match(s,/&& window.set_background_color\(Some\(Color\(0,0,0,0\)\)\)\.is_ok\(\)/);
 assert.doesNotMatch(s,/Effect::(?:Mica|Blur|Tabbed)|DWMSBT_MAINWINDOW/);
 assert.doesNotMatch(css,/backdrop-filter|blur\(|animation|transition|height:|width:/);
 assert.match(s,/RegGetValueW/);assert.doesNotMatch(s,/RegSet|RegCreate|DwmEnableComposition|eval\(/);
 assert.match(s,/None::<WindowEffectsConfig>/);assert.match(s,/DWMSBT_NONE/);
});
test('permissions, dependency graph, identity and window controls stay byte-identical', () => {
 for(const p of ['src-tauri/Cargo.toml','src-tauri/Cargo.lock','src-tauri/tauri.conf.json','src-tauri/build.rs','src-tauri/capabilities/main.json','src-tauri/permissions/host.toml','src-tauri/src/windows/identity.rs','src-tauri/src/windows/window_state.rs','src-tauri/src/window_geometry.rs','src/App.tsx','src/components/TitleBar.tsx','src/components/Sidebar.tsx','src/components/SideStatus.tsx']) assert.equal(read(p),old(p),p);
 const s=read('src-tauri/src/desktop.rs');
 assert.equal(s.replace('          .transparent(true)\n','').replace('        crate::acrylic::install(&window);\n','').replace(/        \/\/ Fixed, main-window-only theme requests;[^\n]*\n        "backdrop-light"\|"backdrop-dark"=>[^\n]*\n/,''),old('src-tauri/src/desktop.rs'));
});
test('only actual theme is sent, gate requires a typed matching native event, and CSS is gated', () => {
 const theme=read('src/lib/theme.ts'),s=read('src/lib/nativeBackdrop.ts'),css=read('src/acrylic.css');
 assert.match(theme,/const KEY = 'kat.theme'/);assert.match(theme,/media.addEventListener\('change', change\)/);
 assert.match(theme,/syncNativeBackdrop\(actual\)/);
 assert.match(s,/listen<Snapshot>\('native-backdrop'/);assert.match(s,/value\?\.enabled !== true/);
 assert.match(s,/value.theme !== desired \|\| contrast.matches/);assert.match(s,/while \(desired && desired !== requested\)/);
 assert.match(css,/\.main\) \{\n  background:transparent/);
 assert.match(css,/\.content \{ background:var\(--content-wash\)/);
 for(const line of css.split('@media')[0].split('\n').filter(l=>l.includes('{')&&!l.startsWith('@'))) assert.ok(line.includes('[data-native-acrylic="enabled"]'),line);
 assert.ok(read('src/main.tsx').endsWith("import './acrylic.css';\n"));
});
