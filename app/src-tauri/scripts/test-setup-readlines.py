#!/usr/bin/env python3
"""Focused non-Windows checks plus a compiled, NOTRUN real NSIS read-line runner.
The portable checks interpret the installed NSIS TrimNewLines core instructions;
only the optional Windows runner executes FileReadUTF16LE/real NSIS VM.
"""
from pathlib import Path
import argparse,json,os,re,shlex,subprocess,unittest
R=Path(__file__).resolve().parents[3]
S=R/'app/src-tauri';OLD=R/'integration-evidence/comprehensive-20261029/native/setup-installer';E=R/'integration-evidence/comprehensive-20261029/native/setup-readline-fix'
script=(S/'scripts/Kat-Setup.nsi').read_text();bridge=(S/'src/windows/setup_bridge.rs').read_text()
textfunc=(OLD/'toolchain/nsis/root/usr/share/nsis/Include/TextFunc.nsh').read_text()
macro=textfunc.split('!macro TrimNewLines_\n',1)[1].split('!macroend',1)[0]
core=macro[macro.index('StrCpy $1 0'):macro.index('Pop $2')]
ops=[shlex.split(x.strip(),posix=False)for x in core.splitlines()if x.strip()]
def trim(value):
    regs={'$0':value,'$1':'','$2':''};pc=0;steps=0
    def expand(v):
        if v in regs:return regs[v]
        return v.strip("'\"").replace('$\\r','\r').replace('$\\n','\n')
    while pc<len(ops):
        steps+=1;assert steps<10000
        op,*args=ops[pc];jump=1
        if op=='StrCpy':
            var,src,*rest=args;v=expand(src);start=int(expand(rest[1]))if len(rest)>1 else 0
            if start<0:start=len(v)+start
            n=int(expand(rest[0]))if rest else 0
            regs[var]=v if not rest else (v[start:][:n]if start>=0 and n>0 else (v[:n]if n<0 else ''))
        elif op=='IntOp':
            var,a,operator,b=args;assert operator in ['+','-'];regs[var]=str(int(expand(a))+(1 if operator=='+'else -1)*int(expand(b)))
        elif op=='StrCmp':
            a,b,yes,*no=args;offset=yes if expand(a)==expand(b)else(no[0]if no else '0');jump=int(offset)or 1
        else:raise AssertionError(op)
        pc+=jump
    return regs['$0']
class Regression(unittest.TestCase):
    def test_01_exact_kind_and_path_with_each_line_ending(self):
        for kind in ['new','update']:
            for root in [r'C:\Program Files\Kat Client',r'C:\Program Files\Kat Client Test',r'C:\Program Files\中文 Kat Client']:
                for end in ['\r\n','\n','\r','']:
                    with self.subTest(kind=kind,root=root,end=repr(end)):
                        self.assertEqual(trim(kind+end),kind);self.assertEqual(trim(root+end),root)
    def test_02_only_actual_trailing_cr_lf_removed(self):
        for value in ['',r'C:\Program Files\Kat Client','ends with e','preserve trailing spaces  ','internal\nnewline intact']:
            self.assertEqual(trim(value),value)
        self.assertEqual(trim('update\r\n\r\n'),'update')
    def test_03_production_reads_ordinary_root_then_trims_then_assigns(self):
        self.assertIn('!include "TextFunc.nsh"',script)
        block=script[script.index(' FileReadUTF16LE $0 $Existing'):script.index(' StrCmp $INSTDIR "" probe_read_error')]
        self.assertIn('FileReadUTF16LE $0 $ProbeRoot',block);self.assertNotIn('FileReadUTF16LE $0 $INSTDIR',block)
        self.assertIn('${TrimNewLines} $Existing $Existing',block)
        self.assertLess(block.index('${TrimNewLines} $ProbeRoot $ProbeRoot'),block.index('StrCpy $INSTDIR $ProbeRoot'))
        self.assertNotRegex(block,r'StrCpy\s+\$(?:Existing|INSTDIR)\s+\$\w+\s+-2')
    def test_04_nsis_owns_all_bridge_feedback(self):
        self.assertNotIn('MessageBox',bridge)
        self.assertNotIn('installed_handoff::message(',bridge)
        self.assertIn('crate::setup_feedback::error_text(&e,uninstall)',bridge)
        self.assertIn('crate::setup_feedback::FOREIGN_SHORTCUT',bridge)
        self.assertIn('crate::setup_feedback::encode(&text)',bridge)
        body=script.split('Function ${PREFIX}ShowBridgeFeedback',1)[1].split('FunctionEnd',1)[0]
        self.assertIn('MessageBoxW(p $HWNDPARENT',body)
        self.assertIn('FileReadUTF16LE $0 $2',body)
        self.assertIn('Call ShowBridgeFeedback',script)
        self.assertIn('!define MUI_CUSTOMFUNCTION_GUIINIT SetupGUIInit',script)
        self.assertLess(script.index('Function SetupGUIInit'),script.index('--setup-probe'))
        self.assertIn('Call un.ShowBridgeFeedback',script)
        self.assertEqual(script.count('Delete "$PLUGINSDIR\\payload\\kat-setup-result.txt"'),4)
        self.assertNotIn('SetForegroundLockTimeout',bridge+script)
    def test_06_size_is_actual_payload_not_zero_or_constant(self):
        build=(S/'scripts/build-setup.py').read_text()
        self.assertIn('AddSize ${PAYLOAD_SIZE_KIB}',script)
        self.assertIn("sum((r['bytes']+1023)//1024 for r in rows if r['path'] in names)",build)
        self.assertIn('payload_kib(first_uninstaller_bytes)',build)
        self.assertIn("a.uninstaller.stat().st_size==first_uninstaller_bytes",build)
    def test_07_uninstall_retry_and_phase_are_distinct(self):
        feedback=(S/'src/setup_feedback.rs').read_text()
        self.assertIn('然后重新运行卸载程序',feedback)
        self.assertIn('然后重新运行安装程序',feedback)
        self.assertIn('if uninstall{"卸载阶段"}else{"安装阶段"}',feedback)
    def test_08_arp_icon_size_are_helper_owned_and_transactional(self):
        arp=(S/'src/windows/installed_app.rs').read_text();install=(S/'src/windows/installer.rs').read_text()
        self.assertIn('root.join("kat-desktop.exe")',arp)
        self.assertIn('("EstimatedSize",estimated)',arp)
        self.assertIn('installed_size_kib(root,runtime)?',arp)
        self.assertIn('"DisplayIcon","EstimatedSize"',arp)
        self.assertIn('super::installed_app::register(&self.root,&self.runtime)?',install)
        self.assertIn('super::installed_app::restore(&super::installed_app::Snapshot(None))?',install)
        self.assertNotIn('WriteRegStr',script) # no duplicate/elevated NSIS authority
    def test_05_no_move_and_normal_token_checks_remain(self):
        self.assertIn('crate::install_location::select(p.to_str(),r)?',bridge)
        self.assertLess(bridge.index('crate::install_location::select('),bridge.index('service_client::setup_elevate('))
        self.assertIn('identity::require_normal_user()?',bridge)
        self.assertIn('RequestExecutionLevel user',script)
def compile_runner():
    E.mkdir(exist_ok=True);(E/'analysis').mkdir(exist_ok=True);(E/'bin').mkdir(exist_ok=True)
    block=script[script.index(' FileReadUTF16LE $0 $Existing'):script.index(' StrCmp $INSTDIR "" probe_read_error')]
    rows=[]
    for kind in ['new','update']:
        for root in [r'C:\Program Files\Kat Client',r'C:\Program Files\Kat Client Test',r'C:\Program Files\中文 Kat Client']:
            for end in [r'$\r$\n',r'$\n',r'$\r','']:
                # Separate fields may use the same explicit terminator. No-terminator
                # cases test the final root line with the required kind separator.
                rows += [f' FileOpen $0 "$PLUGINSDIR\\probe.txt" w',f' FileWriteUTF16LE $0 "{kind}$\\r$\\n{root}{end}"',' FileClose $0',' FileOpen $0 "$PLUGINSDIR\\probe.txt" r',block,f' StrCmp $Existing "{kind}" +2',' Goto failed',f' StrCmp $INSTDIR "{root}" +2',' Goto failed']
    source='''Unicode true
Target amd64-unicode
RequestExecutionLevel user
Name "Kat read-line regression (no installation)"
OutFile "${OUTPUT}"
SilentInstall silent
!include "TextFunc.nsh"
Var Existing
Var ProbeRoot
Var DesktopDefault
Section
 InitPluginsDir
'''+ '\n'.join(rows)+'''
 MessageBox MB_OK|MB_SETFOREGROUND "24 real UTF16 line-reading cases PASS. No service or installation changes."
 SetErrorLevel 0
 Goto done
 failed:
 MessageBox MB_OK|MB_ICONSTOP|MB_SETFOREGROUND "Read-line regression FAILED. No service or installation changes."
 SetErrorLevel 1
 done:
SectionEnd
'''
    p=E/'analysis/readline-regression.nsi';p.write_text(source)
    env=dict(os.environ,NSISDIR=str(OLD/'toolchain/nsis/root/usr/share/nsis'))
    subprocess.run([str(OLD/'toolchain/nsis/root/usr/bin/makensis'),'-V2','-DOUTPUT='+str(E/'bin/Setup-Readline-Regression.exe'),str(p)],check=True,env=env)
    print('Real NSIS UTF16 runner compiled (24 cases), NOTRUN; Windows execution belongs to controller.')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--compile-runner',action='store_true');a=p.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Regression);result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
    if a.compile_runner:compile_runner()
