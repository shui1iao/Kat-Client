//! Kat-owned Microsoft IP Helper ABI recovery. No physical-interface writes.
//! ABI: learn.microsoft.com/windows/win32/api/netioapi/ and official Windows SDK.
use super::journal::*;
use crate::error::{Error,Result};
use windows_sys::{core::GUID,Win32::{Devices::DeviceAndDriverInstallation::{CM_Locate_DevNodeW,CM_LOCATE_DEVNODE_PHANTOM,CR_NO_SUCH_DEVNODE},Foundation::*,Networking::WinSock::*,NetworkManagement::{IpHelper::*,Ndis::*}}};
pub(super) unsafe fn is_uninstalled_tombstone(oper:i32,guid:&str,luid_val:u64)->bool{
 if oper!=2||luid_val==0||!guid_ok(guid){return false}
 let instance=super::super::identity::wide(&format!(r"SWD\Wintun\{{{guid}}}"));
 let mut dev=0u32;
 if CM_Locate_DevNodeW(&mut dev,instance.as_ptr(),CM_LOCATE_DEVNODE_PHANTOM)!=CR_NO_SUCH_DEVNODE{return false}
 for fam in [AF_INET,AF_INET6]{
  let mut r=MIB_IPINTERFACE_ROW::default();r.Family=fam;r.InterfaceLuid=luid(luid_val);
  if GetIpInterfaceEntry(&mut r)!=ERROR_NOT_FOUND{return false}
 }
 true
}
use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};
fn bad(code:&'static str)->Error{Error::new(code,"Owned TUN recovery could not be verified")}
fn rc(n:u32)->Result<()> {if n==0{Ok(())}else{Err(bad("RECOVERY_OS").native(n))}}
fn text(g:GUID)->String{format!("{:08x}-{:04x}-{:04x}-{}-{}",g.data1,g.data2,g.data3,hex::encode(&g.data4[..2]),hex::encode(&g.data4[2..]))}
fn luid(v:u64)->NET_LUID_LH{NET_LUID_LH{Value:v}}
fn addr(s:&str)->Result<SOCKADDR_INET>{match s.parse::<IpAddr>().map_err(|_|bad("JOURNAL_VALUE"))?{
 IpAddr::V4(v)=>{let mut a=SOCKADDR_IN::default();a.sin_family=AF_INET;a.sin_addr.S_un.S_addr=u32::from_ne_bytes(v.octets());Ok(SOCKADDR_INET{Ipv4:a})},
 IpAddr::V6(v)=>{let mut a=SOCKADDR_IN6::default();a.sin6_family=AF_INET6;a.sin6_addr.u.Byte=v.octets();Ok(SOCKADDR_INET{Ipv6:a})}
}}
unsafe fn ip(a:&SOCKADDR_INET)->Result<String>{match a.si_family{AF_INET=>Ok(Ipv4Addr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).to_string()),AF_INET6=>Ok(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte).to_string()),_=>Err(bad("JOURNAL_VALUE"))}}
pub fn check_compartment(a:&Adapter)->Result<()> {if a.compartment!=1||unsafe{GetCurrentThreadCompartmentId()}!=a.compartment{return Err(bad("RECOVERY_COMPARTMENT"))}Ok(())}
// Complete table read distinguishes genuinely absent from a query error.
pub fn adapter_present(a:&Adapter)->Result<bool>{check_compartment(a)?;unsafe{
 let mut t=std::ptr::null_mut();rc(GetIfTable2(&mut t))?;if t.is_null(){return Err(bad("INTERFACE_QUERY"))}
 let n=(*t).NumEntries as usize;if n>65536{FreeMibTable(t.cast());return Err(bad("INTERFACE_QUERY"))}
 let result=(||{
 let rows=std::slice::from_raw_parts((*t).Table.as_ptr(),n);
 if let Some(r)=rows.iter().find(|r|r.InterfaceLuid.Value==a.luid){
 let g=text(r.InterfaceGuid);
 if g!=a.guid{return Err(bad("RECOVERY_CONFLICT"))}
 let end=r.Alias.iter().position(|&v|v==0).unwrap_or(r.Alias.len());
 if String::from_utf16_lossy(&r.Alias[..end])!=a.alias{return Err(bad("RECOVERY_CONFLICT"))}
 if is_uninstalled_tombstone(r.OperStatus,&g,r.InterfaceLuid.Value){return Ok(false)}
 return Ok(true)
 }
 if rows.iter().any(|r|{let g=text(r.InterfaceGuid);g==a.guid&&!is_uninstalled_tombstone(r.OperStatus,&g,r.InterfaceLuid.Value)}){return Err(bad("RECOVERY_CONFLICT"))}Ok(false)
 })();FreeMibTable(t.cast());result
}}
pub fn bind_adapter(a:&Adapter)->Result<()> {if a.luid==0||!adapter_present(a)?{return Err(bad("JOURNAL_ADAPTER"))}Ok(())}
fn route_row(a:&Adapter,v:&RouteValue)->Result<MIB_IPFORWARD_ROW2>{let mut r=MIB_IPFORWARD_ROW2::default();unsafe{InitializeIpForwardEntry(&mut r)};r.InterfaceLuid=luid(a.luid);r.DestinationPrefix.Prefix=addr(&v.destination)?;r.DestinationPrefix.PrefixLength=v.prefix;r.NextHop=addr(&v.next_hop)?;r.Metric=v.metric;r.Protocol=v.protocol as i32;r.SitePrefixLength=v.site_prefix;r.ValidLifetime=v.valid_lifetime;r.PreferredLifetime=v.preferred_lifetime;r.Loopback=v.loopback;r.AutoconfigureAddress=v.autoconfigure;r.Publish=v.publish;r.Immortal=v.immortal;Ok(r)}
unsafe fn route_value(r:&MIB_IPFORWARD_ROW2)->Result<Value>{Ok(Value{route:Some(RouteValue{destination:ip(&r.DestinationPrefix.Prefix)?,prefix:r.DestinationPrefix.PrefixLength,next_hop:ip(&r.NextHop)?,scope:if r.NextHop.si_family==AF_INET6{r.NextHop.Ipv6.Anonymous.sin6_scope_id}else{0},metric:r.Metric,protocol:r.Protocol as u32,site_prefix:r.SitePrefixLength,valid_lifetime:r.ValidLifetime,preferred_lifetime:r.PreferredLifetime,loopback:r.Loopback,autoconfigure:r.AutoconfigureAddress,publish:r.Publish,immortal:r.Immortal,origin:r.Origin as u32}),address:None,interface:None,dns:None})}
fn address_row(a:&Adapter,v:&AddressValue)->Result<MIB_UNICASTIPADDRESS_ROW>{let mut r=MIB_UNICASTIPADDRESS_ROW::default();unsafe{InitializeUnicastIpAddressEntry(&mut r)};r.InterfaceLuid=luid(a.luid);r.Address=addr(&v.address)?;r.OnLinkPrefixLength=v.prefix;r.PrefixOrigin=v.prefix_origin as i32;r.SuffixOrigin=v.suffix_origin as i32;r.SkipAsSource=v.skip_as_source;Ok(r)}
pub fn read(a:&Adapter,c:&Change)->Result<Option<Value>>{check_compartment(a)?;
 if let Some(v)=&c.installed.route {let mut r=route_row(a,v)?;let n=unsafe{GetIpForwardEntry2(&mut r)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;let _=adapter_present(a)?;return unsafe{route_value(&r).map(Some)}}
 if !adapter_present(a)?{return Ok(None)}
 if let Some(v)=&c.installed.address {let mut r=address_row(a,v)?;let n=unsafe{GetUnicastIpAddressEntry(&mut r)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;return Ok(Some(Value{route:None,address:Some(AddressValue{address:v.address.clone(),prefix:r.OnLinkPrefixLength,prefix_origin:r.PrefixOrigin as u32,suffix_origin:r.SuffixOrigin as u32,skip_as_source:r.SkipAsSource}),interface:None,dns:None}))}
 if let Some(v)=&c.installed.interface {let mut r=MIB_IPINTERFACE_ROW::default();r.Family=v.family;r.InterfaceLuid=luid(a.luid);let n=unsafe{GetIpInterfaceEntry(&mut r)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;return Ok(Some(Value{route:None,address:None,interface:Some(InterfaceValue{family:r.Family,mtu:r.NlMtu,metric:r.Metric,automatic_metric:r.UseAutomaticMetric,dad_transmits:r.DadTransmits}),dns:None}))}
 if c.installed.dns.is_some(){let mut g=GUID::default();let n=unsafe{ConvertInterfaceLuidToGuid(&luid(a.luid),&mut g)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;let mut s=DNS_INTERFACE_SETTINGS::default();s.Version=DNS_INTERFACE_SETTINGS_VERSION1;let n=unsafe{GetInterfaceDnsSettings(g,&mut s)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;let servers=unsafe{super::super::identity::string(s.NameServer)};unsafe{FreeInterfaceDnsSettings(&mut s)};return Ok(Some(Value{route:None,address:None,interface:None,dns:Some(DnsValue{servers})}))}
 Err(bad("JOURNAL_VALUE"))
}
// Caller has durable WAL and a current==installed CAS match. Recheck immediately
// before mutation; query error never grants delete/restore permission.
pub fn restore(a:&Adapter,c:&Change)->Result<()> {
 let current=read(a,c)?;
 if cas(c,&current)==Cas::AlreadyOriginal{return Ok(())}
 if cas(c,&current)!=Cas::Restore{return Err(bad("RECOVERY_CONFLICT"))}
 if let Some(v)=&c.installed.route{let r=route_row(a,v)?;let n=unsafe{DeleteIpForwardEntry2(&r)};if n!=ERROR_NOT_FOUND{rc(n)?}}
 else if let Some(v)=&c.installed.address{let r=address_row(a,v)?;let n=unsafe{DeleteUnicastIpAddressEntry(&r)};if n!=ERROR_NOT_FOUND{rc(n)?}}
 else if let Some(v)=c.before.as_ref().and_then(|v|v.interface.as_ref()){
 let mut r=MIB_IPINTERFACE_ROW::default();r.Family=v.family;r.InterfaceLuid=luid(a.luid);rc(unsafe{GetIpInterfaceEntry(&mut r)})?;
 r.NlMtu=v.mtu;r.Metric=v.metric;r.UseAutomaticMetric=v.automatic_metric;r.DadTransmits=v.dad_transmits;r.SitePrefixLength=0;rc(unsafe{SetIpInterfaceEntry(&mut r)})?
 }else if let Some(v)=c.before.as_ref().and_then(|v|v.dns.as_ref()){
 let mut g=GUID::default();rc(unsafe{ConvertInterfaceLuidToGuid(&luid(a.luid),&mut g)})?;let mut s=DNS_INTERFACE_SETTINGS::default();s.Version=DNS_INTERFACE_SETTINGS_VERSION1;s.Flags=DNS_SETTING_NAMESERVER as u64;let mut text=super::super::identity::wide(&v.servers);s.NameServer=text.as_mut_ptr();rc(unsafe{SetInterfaceDnsSettings(g,&s)})?
 }else{return Err(bad("JOURNAL_BEFORE"))}
 if read(a,c)?!=c.before{return Err(bad("RECOVERY_READBACK"))}Ok(())
}

pub fn alias_present(alias:&str)->Result<bool>{unsafe{
 let mut t=std::ptr::null_mut();rc(GetIfTable2(&mut t))?;if t.is_null(){return Err(bad("INTERFACE_QUERY"))}let n=(*t).NumEntries as usize;if n>65536{FreeMibTable(t.cast());return Err(bad("INTERFACE_QUERY"))}
 let found=std::slice::from_raw_parts((*t).Table.as_ptr(),n).iter().any(|r|{let end=r.Alias.iter().position(|&v|v==0).unwrap_or(r.Alias.len());String::from_utf16_lossy(&r.Alias[..end])==alias&&!is_uninstalled_tombstone(r.OperStatus,&text(r.InterfaceGuid),r.InterfaceLuid.Value)});FreeMibTable(t.cast());Ok(found)
}}
pub fn discover_adapter(a:&Adapter)->Result<Option<Adapter>>{unsafe{
 let mut t=std::ptr::null_mut();rc(GetIfTable2(&mut t))?;if t.is_null(){return Err(bad("INTERFACE_QUERY"))}let n=(*t).NumEntries as usize;if n>65536{FreeMibTable(t.cast());return Err(bad("INTERFACE_QUERY"))}
 let result=(||{for r in std::slice::from_raw_parts((*t).Table.as_ptr(),n){let end=r.Alias.iter().position(|&v|v==0).unwrap_or(r.Alias.len());let alias=String::from_utf16_lossy(&r.Alias[..end]);let g=text(r.InterfaceGuid);if g==a.guid {if alias!=a.alias{return Err(bad("RECOVERY_CONFLICT"))}if is_uninstalled_tombstone(r.OperStatus,&g,r.InterfaceLuid.Value){continue}let mut b=a.clone();b.luid=r.InterfaceLuid.Value;return Ok(Some(b))}if alias==a.alias{if is_uninstalled_tombstone(r.OperStatus,&g,r.InterfaceLuid.Value){continue}return Err(bad("RECOVERY_CONFLICT"))}}Ok(None)})();FreeMibTable(t.cast());result
}}

#[derive(Debug,Clone,PartialEq,Eq)]pub(super) struct AliasRow{pub adapter:Adapter,pub index:u32,pub oper:i32}
pub(super) fn alias_row(alias:&str)->Result<Option<AliasRow>>{unsafe{
 if GetCurrentThreadCompartmentId()!=1{return Err(bad("RECOVERY_COMPARTMENT"))}
 let mut t=std::ptr::null_mut();rc(GetIfTable2(&mut t))?;if t.is_null(){return Err(bad("INTERFACE_QUERY"))}
 let n=(*t).NumEntries as usize;if n>65536{FreeMibTable(t.cast());return Err(bad("INTERFACE_QUERY"))}
 let result=(||{let mut found=None;for r in std::slice::from_raw_parts((*t).Table.as_ptr(),n){
  let end=r.Alias.iter().position(|&v|v==0).ok_or_else(||bad("INTERFACE_QUERY"))?;
  let name=String::from_utf16(&r.Alias[..end]).map_err(|_|bad("INTERFACE_QUERY"))?;
  let g=text(r.InterfaceGuid);
  if name==alias&&!is_uninstalled_tombstone(r.OperStatus,&g,r.InterfaceLuid.Value) {if found.is_some(){return Err(bad("LEGACY_ADAPTER_PRESENT"))}found=Some(AliasRow{adapter:Adapter{alias:name,guid:g,luid:r.InterfaceLuid.Value,compartment:1},index:r.InterfaceIndex,oper:r.OperStatus});}
 }Ok(found)})();FreeMibTable(t.cast());result
}}
