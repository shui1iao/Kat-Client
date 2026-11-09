//! Closed transport observations only. Never stores frame bytes or arbitrary serde text.
use serde::{Deserialize,Serialize};
use crate::error::{Error,Result};
use tokio::io::{AsyncRead,AsyncBufRead,ReadBuf};
use std::{pin::Pin,task::{Context,Poll}};
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="snake_case")]
pub enum Branch{FrameLimit,JsonDecode,ResponseShape,SubscriptionReason,ResourceDetail,TunDetail,TransportDetail,IdUnmatched,TruncatedEof,Eof,Read,Write,Timeout}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="snake_case")]
pub enum Shape{IdEmpty,IdLength,ResultMissing,SuccessError,ErrorMissing,ErrorWithResult}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="snake_case")]
pub enum JsonCategory{Io,Syntax,Data,Eof}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]#[serde(deny_unknown_fields)]
pub struct Detail{
 pub branch:Branch,
 #[serde(default,skip_serializing_if="Option::is_none")]pub shape:Option<Shape>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub frame_len:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub observed_bytes:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub limit:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub id_len:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub request_id:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub json_category:Option<JsonCategory>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub line:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub column:Option<u64>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub native:Option<u32>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub remote_branch:Option<Branch>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub remote_native:Option<u32>,
}
impl Detail{
 pub fn new(branch:Branch)->Self{Self{branch,shape:None,frame_len:None,observed_bytes:None,limit:None,id_len:None,request_id:None,json_category:None,line:None,column:None,native:None,remote_branch:None,remote_native:None}}
 pub fn valid(&self)->bool{self.native!=Some(0)&&self.remote_native!=Some(0)&&[self.frame_len,self.observed_bytes,self.limit,self.id_len,self.request_id,self.line,self.column].iter().all(|n|n.is_none_or(|v|v<=9007199254740991))}
}
pub fn fallback(e:&Error)->Option<Detail>{let branch=match e.code.as_str(){"CORE_READ"=>Branch::Read,"CORE_WRITE"=>Branch::Write,"CORE_EOF"=>Branch::Eof,"CORE_TIMEOUT"=>Branch::Timeout,_=>return None};let mut d=Detail::new(branch);d.native=e.os_error;Some(d)}
// Observe the ORIGINAL production read_frame without altering its decisions.
// Count consumed/available bytes, not an unrelated previous successful status.
struct Observed<'a,R>{inner:&'a mut R,consumed:usize,available:usize,complete:bool}
impl<R:AsyncBufRead+Unpin> AsyncRead for Observed<'_,R>{fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,b:&mut ReadBuf<'_>)->Poll<std::io::Result<()>>{Pin::new(&mut*self.inner).poll_read(cx,b)}}
impl<R:AsyncBufRead+Unpin> AsyncBufRead for Observed<'_,R>{
 fn poll_fill_buf(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<&[u8]>>{let s=self.get_mut();s.available=0;s.complete=false;match Pin::new(&mut*s.inner).poll_fill_buf(cx){Poll::Ready(Ok(b))=>{let end=b.iter().position(|x|*x==b'\n');s.available=end.unwrap_or(b.len());s.complete=end.is_some();Poll::Ready(Ok(b))},x=>x}}
 fn consume(self:Pin<&mut Self>,n:usize){let s=self.get_mut();s.consumed=s.consumed.saturating_add(n);Pin::new(&mut*s.inner).consume(n);s.available=0;s.complete=false;}
}
pub async fn read_frame<R:AsyncBufRead+Unpin>(reader:&mut R)->Result<Option<Vec<u8>>>{
 let mut observed=Observed{inner:reader,consumed:0,available:0,complete:false};
 crate::supervisor::read_frame(&mut observed).await.map_err(|e|{
  let branch=match e.code.as_str(){"FRAME_TOO_LARGE"=>Branch::FrameLimit,"CORE_PROTOCOL"=>Branch::TruncatedEof,_=>Branch::Read};let mut d=Detail::new(branch);d.native=e.os_error;d.observed_bytes=Some(observed.consumed.saturating_add(observed.available)as u64);
  if branch==Branch::TruncatedEof{d.frame_len=Some(observed.consumed as u64);}else if branch==Branch::FrameLimit{d.limit=Some(crate::protocol::MAX_FRAME as u64);if observed.complete{d.frame_len=d.observed_bytes;}}
  e.transport(d)
 })
}
#[cfg(test)]mod tests{use super::*;
 #[tokio::test]async fn exact_lengths_not_last_status(){let mut r=tokio::io::BufReader::with_capacity(3,&b"abc"[..]);let e=read_frame(&mut r).await.unwrap_err();let d=e.transport.unwrap();assert_eq!(d.branch,Branch::TruncatedEof);assert_eq!(d.frame_len,Some(3));assert_eq!(d.observed_bytes,Some(3));}
 #[test]fn no_arbitrary_fields_or_zero_native(){assert!(serde_json::from_str::<Detail>(r#"{"branch":"https://private"}"#).is_err());assert!(serde_json::from_str::<Detail>(r#"{"branch":"read","raw":"secret"}"#).is_err());let mut d=Detail::new(Branch::Read);d.native=Some(0);assert!(!d.valid());}
}
