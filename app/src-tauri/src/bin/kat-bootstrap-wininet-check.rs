// Standalone acceptance tool, excluded from product payload. Read-only API only.
#[cfg(windows)]fn main(){
 if std::env::args_os().len()!=1{println!("{{\"supported\":false,\"category\":\"arguments_refused\"}}");std::process::exit(2);}
 if kat_host::windows::identity::require_normal_user().is_err(){println!("{{\"supported\":false,\"category\":\"normal_user_required\"}}");std::process::exit(2);}
 match kat_host::windows::proxy::bootstrap_endpoint(){Ok(_)=>println!("{{\"supported\":true}}"),Err(e)=>{let c=e.detail.map(|d|d.category).unwrap_or_else(||"proxy_read_failed".into());let safe=match c.as_str(){"proxy_unsupported"=>"proxy_unsupported",_=>"proxy_read_failed"};println!("{{\"supported\":false,\"category\":\"{}\"}}",safe);}}
}
#[cfg(not(windows))]fn main(){println!("{{\"supported\":false,\"category\":\"windows_required\"}}");}
