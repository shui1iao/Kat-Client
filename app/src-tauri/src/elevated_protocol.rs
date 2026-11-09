//! Fixed elevated roles only. This wire never accepts executable/file/OS paths.
use crate::error::{Error,Result};
use serde::{Deserialize,Serialize};
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(tag="op",rename_all="snake_case",deny_unknown_fields)]
pub enum ElevatedRequest {
 Prepare{old_pid:u32,old_stamp:u64},
 TunDiagnostic{lease:String,detail:crate::tun_diagnostics::Detail},
 Claim{lease:String},
 Status{lease:String},
 Abort{lease:String},
 Bind{lease:String},
 Commit{lease:String,checkpoint:Checkpoint},
 Authorize{lease:String,proof:String},
 Shutdown{lease:String,force:bool},
 #[cfg(windows)] Journal{lease:String,request:crate::windows::core_tun_recovery::WriteRequest},
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint{pub schema:u32,pub source_sha256:String,pub history_sha256:String}
impl Checkpoint{pub fn validate(&self)->Result<()>{if self.schema!=1||![&self.source_sha256,&self.history_sha256].iter().all(|s|hex_value(s,64)){return Err(Error::new("HANDOVER_CHECKPOINT","Invalid persistence checkpoint"));}Ok(())}}
pub fn hex_value(s:&str,n:usize)->bool{s.len()==n&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
impl ElevatedRequest{pub fn validate(&self)->Result<()>{
 match self {Self::Prepare{old_pid,old_stamp}=>if *old_pid==0||*old_stamp==0{return Err(Error::new("LAUNCH_IDENTITY","Previous core identity required"));},
 #[cfg(windows)] Self::Journal{lease,..}=>if !hex_value(lease,64){return Err(Error::new("LAUNCH_LEASE","Invalid launch lease"));},
 Self::TunDiagnostic{lease,..}|Self::Claim{lease}|Self::Status{lease}|Self::Abort{lease}|Self::Bind{lease}|Self::Shutdown{lease,..}|Self::Authorize{lease,..}|Self::Commit{lease,..}=>if !hex_value(lease,64){return Err(Error::new("LAUNCH_LEASE","Invalid launch lease"));}}
 if let Self::Commit{checkpoint,..}=self{checkpoint.validate()?;}if let Self::Authorize{proof,..}=self{if !hex_value(proof,64){return Err(Error::new("LAUNCH_PROOF","Invalid handover proof"));}}Ok(())
}}
