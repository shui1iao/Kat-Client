#!/usr/bin/env python3
"""Portable completion-page/name policy checks, plus the full NSIS runner compile.
No Windows install, shortcut or launch is executed by this test.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,tempfile,unittest
R=Path(__file__).resolve().parents[3];S=R/'app/src-tauri'
n=(S/'scripts/Kat-Setup.nsi').read_text();b=(S/'src/windows/setup_bridge.rs').read_text();links=(S/'src/windows/shortcuts.rs').read_text();loc=(S/'src/windows/install_location.rs').read_text()
class Finish(unittest.TestCase):
 def test_visible_name_and_fixed_internal_identity(self):
  self.assertIn('Name "Kat"',n);self.assertIn('InstallDir "$PROGRAMFILES64\\Kat"',n)
  c=json.loads((S/'tauri.conf.json').read_text());self.assertEqual(c['productName'],'Kat');self.assertEqual(c['identifier'],'app.kat.client');self.assertEqual(c['app']['windows'][0]['title'],'Kat')
  self.assertIn('SOFTWARE\\Kat Client Installation',loc);self.assertIn('.join("Kat Client").join("Runtime")',loc)
  self.assertIn('"KatClientNetwork"',(S/'src/windows/scm.rs').read_text());self.assertIn('Uninstall\\Kat Client',(S/'src/windows/installed_app.rs').read_text())
 def test_gui_does_not_launch_until_explicit_finish_run(self):
  self.assertIn('!define MUI_FINISHPAGE_RUN_NOTCHECKED',n);self.assertIn('MUI_FINISHPAGE_RUN_TEXT "立即运行 Kat"',n)
  self.assertIn('MUI_FINISHPAGE_RUN_FUNCTION FinishRun',n);self.assertIn('if uninstall||deferred{return Ok(());}',b)
  self.assertLess(b.index('if uninstall||deferred{return Ok(());}'),b.index('let mut pending=installed_handoff::prepare().map_err'))
  self.assertIn('--setup-run',n);self.assertIn('args==["--setup-run"]',b)
 def test_desktop_new_default_and_upgrade_preserved(self):
  self.assertIn('MUI_FINISHPAGE_SHOWREADME_TEXT "创建桌面快捷方式"',n);self.assertIn('MUI_PAGE_CUSTOMFUNCTION_SHOW FinishShow',n)
  self.assertIn('StrCmp $DesktopDefault "0"',n);self.assertIn('${BST_UNCHECKED}',n)
  self.assertIn('new_install||desktop.join("Kat.lnk").exists()||desktop.join("Kat Client.lnk").exists()',links)
  self.assertIn('--setup-shortcuts "$INSTDIR" "$DesktopChoice"',n);self.assertIn('crate::install_location::select(root.to_str(),&args[1])?',b)
 def test_links_rename_deduplicate_without_touching_foreign(self):
  self.assertIn('for name in ["Kat.lnk","Kat Client.lnk"]',links)
  self.assertIn('uninstall||name=="Kat Client.lnk"||(index==0&&!desktop)',links)
  for guard in ['ordinary_link(&before)','security::same_path(&v.target,&exe)','std::fs::read(&p).ok().as_ref()!=Some(&before)','pending.record(p,Some(before),None)','foreign=true;continue;']:
   self.assertIn(guard,links)
  self.assertIn('pending.rollback()',links);self.assertIn('index==0&&!desktop',links) # menu index 1 always written
 def test_upgrade_no_move_and_silent_never_launches(self):
  self.assertIn('StrCmp $Existing "update"',n);self.assertIn('crate::install_location::select(p.to_str(),r)?',b)
  install=n.split('Section "安装 Kat"',1)[1].split('SectionEnd',1)[0]
  self.assertIn('--defer-launch',install);self.assertEqual(install.count('--setup-install'),1)
  self.assertNotIn('IfSilent',install)
 def test_service_visible_name_rollback(self):
  i=(S/'src/windows/installer.rs').read_text();self.assertIn('wide("Kat").as_ptr(),SERVICE_ALL_ACCESS',i);self.assertIn('scm::set_display_name(&self.service,"Kat")?',i);self.assertIn('scm::display_name(&old)?',i);self.assertIn('scm::set_display_name(&self.service,name)?',i)
 def test_mui_leave_applies_both_states_before_run(self):
  mui=(R/'integration-evidence/comprehensive-20261029/native/setup-installer/toolchain/nsis/root/usr/share/nsis/Contrib/Modern UI 2/Pages/Finish.nsh').read_text()
  leave=mui.split('Function "${LEAVE}"',1)[1];self.assertLess(leave.index('MUI_PAGE_FUNCTION_CUSTOM LEAVE'),leave.index('MUI_FINISHPAGE_RUN'))
  self.assertIn('MUI_PAGE_CUSTOMFUNCTION_LEAVE FinishLeave',n);self.assertIn('${NSD_GetState} $mui.FinishPage.ShowReadme $DesktopChoice',n)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--compile-runner',action='store_true');args=parser.parse_args()
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Finish));assert result.wasSuccessful()
 if args.compile_runner:
  E=Path('/opt/kat-ui-next-20261101/candidate16/installer-tests');E.mkdir(parents=True,exist_ok=True)
  payload=E/'payload';shutil.copytree(R/'deliverables/payload',payload,dirs_exist_ok=True);shutil.copy2(R/'deliverables/bin/kat-install-helper.exe',payload/'kat-install-helper.exe')
  subprocess.run(['python3',str(S/'scripts/build-setup.py'),'--payload',str(payload),'--output',str(E/'Kat-Setup-compile-only.exe'),'--uninstaller',str(E/'Kat-Uninstall-compile-only.exe')],check=True)
  (E/'RESULTS.json').write_text(json.dumps({'portable_passed':result.testsRun,'full_NSIS_compiled':True,'Windows_runtime':'NOTRUN; compile only, old payload not a deliverable'},indent=2)+'\n')
