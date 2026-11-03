//! Private new-adapter readiness gate. The sole budget includes alias AND both IP rows.
use crate::{error::{Error,Result},service_protocol::IfSettings};
use std::time::Duration;
const BUDGET:Duration=Duration::from_secs(10);
const TICK:Duration=Duration::from_millis(100);
pub(crate) trait Io {
 fn elapsed(&self)->Duration;
 fn alive(&mut self)->Result<()>;
 fn alias(&mut self)->Result<u64>;
 fn guid(&mut self,luid:u64)->Result<String>;
 fn identity(&mut self,luid:u64)->Result<Option<String>>;
 fn bind(&mut self,luid:u64,guid:&str)->Result<()>;
 fn query(&mut self,luid:u64,family:u16)->std::result::Result<(u64,IfSettings),u32>;
 fn tick(&mut self,duration:Duration);
 /// Identity the alias already resolved to before this start spawned its bridge (e.g. an orphaned adapter of a killed bridge).
 fn preexisting(&self)->Option<(u64,String)>{None}
}
pub(crate) struct Ready{pub luid:u64,pub originals:[IfSettings;2]}
fn invalid()->Error{Error::new("INTERFACE_IDENTITY","TUN interface identity changed or could not be verified")}
// Exactly the netapi::guid_text form persisted in journals (8-4-4-16 lower hex), and not all-zero.
fn guid_text_valid(g:&str)->bool{let b=g.as_bytes();b.len()==35&&b.iter().enumerate().all(|(i,c)|if matches!(i,8|13|18){*c==b'-'}else{c.is_ascii_digit()||(b'a'..=b'f').contains(c)})&&b.iter().any(|c|*c!=b'0'&&*c!=b'-')}
fn deadline(io:&impl Io,bound:bool)->Result<()>{if io.elapsed()>=BUDGET{Err(Error::new(if bound{"INTERFACE_QUERY"}else{"TUN_NOT_READY"},"TUN interface did not become ready"))}else{Ok(())}}
fn step<I:Io,T>(io:&mut I,bound:bool,f:impl FnOnce(&mut I)->Result<T>)->Result<T>{deadline(io,bound)?;let v=f(io);deadline(io,bound)?;v}
fn same<I:Io>(io:&mut I,l:u64,g:&str)->Result<()>{
 if step(io,true,|io|io.alias()).map_err(|e|if e.code=="INTERFACE_QUERY"{e}else{invalid()})?!=l{return Err(invalid());}
 if step(io,true,|io|io.guid(l))?!=g{return Err(invalid());}
 if step(io,true,|io|io.identity(l))?.as_deref()!=Some(g){return Err(invalid());}Ok(())
}
pub(crate) fn wait<I:Io>(io:&mut I)->Result<Ready>{
 let mut bound:Option<(u64,String)>=None;
 loop{
  step(io,bound.is_some(),|io|io.alive())?;
  if bound.is_none(){
   // Preserve the original bounded alias-discovery behavior, not a new global retry.
   if let Ok(l)=step(io,false,|io|Ok(io.alias()))?{
    if l==0{return Err(invalid());}
    // Nothing is owned or written before bind: an object vanishing between alias and GUID lookup is just not ready yet.
    if let Ok(g)=step(io,false,|io|Ok(io.guid(l)))?{
     if !guid_text_valid(&g){return Err(invalid());}
     // Never adopt the pre-spawn identity: Wintun removes that orphan when the new bridge creates its adapter.
     if io.preexisting().as_ref()!=Some(&(l,g.clone())){step(io,true,|io|io.bind(l,&g))?;bound=Some((l,g));}
    }
   }
  }
  if let Some((l,g))=&bound{
   same(io,*l,g)?;
   let mut rows=[None,None];
   for(slot,family)in [2,23].into_iter().enumerate(){
    match step(io,true,|io|Ok(io.query(*l,family)))?{
     Ok((key,row))=>{if key!=*l||row.family!=family{return Err(invalid());}rows[slot]=Some(row);},
     Err(1168)=>{}, // Only a new adapter's pre-write IP row may still be pending.
     Err(_)=>return Err(Error::new("INTERFACE_QUERY","Cannot query TUN interface settings")),
    }
   }
   same(io,*l,g)?;step(io,true,|io|io.alive())?;
   if let [Some(v4),Some(v6)]=rows{return Ok(Ready{luid:*l,originals:[v4,v6]});}
  }
  let remaining=BUDGET.saturating_sub(io.elapsed());deadline(io,bound.is_some())?;
  io.tick(remaining.min(TICK));
 }
}
#[cfg(test)]#[path="tun_ready_tests.rs"]mod tests;
