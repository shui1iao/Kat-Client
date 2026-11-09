#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
fn main() {
    use kat_host::{installer_result::{InstallerOutcome, report_exit, EXIT_REPORT_IDENTITY},
        windows::{installer, installer_result::UserResultWriter}};
    let a: Vec<String> = std::env::args().skip(1).collect();
    let fixed = (a.len()==7 && matches!(a.first().map(String::as_str),Some("--setup-install")) && a[5]=="--root")
        || (a.len()==7 && a[0]=="--core-update" && a[5]=="--offer")
        || (a.len()==7 && matches!(a[0].as_str(),"--update-finalize"|"--update-rollback") && a[5]=="--tx")
        || (a.len()==5 && a[0]=="--update-recover");
    if !fixed || a[1]!="--gui" || a[3]!="--stamp" {std::process::exit(1);}
    let (Ok(pid),Ok(stamp))=(a[2].parse::<u32>(),a[4].parse::<u64>()) else {std::process::exit(EXIT_REPORT_IDENTITY as i32)};
    // Capture the actual ordinary-user token before ANY result-path IO. The
    // installer independently verifies the approved image, stamp, SID and session.
    let writer=match UserResultWriter::capture(pid,stamp){Ok(w)=>w,Err(_)=>std::process::exit(EXIT_REPORT_IDENTITY as i32)};
    let result=match a[0].as_str(){
        "--setup-install"=>installer::setup(false,pid,stamp,Some(&a[6])),
        "--core-update"=>installer::core_update(pid,stamp,&a[6]),
        "--update-finalize"=>installer::finish_update(pid,stamp,&a[6],true),
        "--update-rollback"=>installer::finish_update(pid,stamp,&a[6],false),
        "--update-recover"=>installer::recover_update(pid,stamp),
        _=>unreachable!(),
    };
    let code=report_exit(&result,writer.write(&InstallerOutcome::from_result(&result))) as i32;
    if code!=0 {std::process::exit(code);}
}
#[cfg(not(windows))]
fn main(){std::process::exit(2);}
