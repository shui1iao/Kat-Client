use crate::{error::{Error,Result},service_protocol::{Physical,Route,Address,IfSettings}};
use super::identity::{wide,string};
use std::{net::{IpAddr,Ipv4Addr,Ipv6Addr}};
use sha2::{Sha256,Digest};
use windows_sys::{core::GUID,Win32::{Foundation::*,Networking::WinSock::*,NetworkManagement::{IpHelper::*,Ndis::*}}};
pub fn sockaddr(ip:IpAddr)->SOCKADDR_INET{match ip{
 IpAddr::V4(v)=>{let mut a=SOCKADDR_IN::default();a.sin_family=AF_INET;a.sin_addr.S_un.S_addr=u32::from_ne_bytes(v.octets());SOCKADDR_INET{Ipv4:a}},
 IpAddr::V6(v)=>{let mut a=SOCKADDR_IN6::default();a.sin6_family=AF_INET6;a.sin6_addr.u.Byte=v.octets();SOCKADDR_INET{Ipv6:a}}
}}
pub unsafe fn ip(a:&SOCKADDR_INET)->Result<IpAddr>{match a.si_family{AF_INET=>Ok(IpAddr::V4(Ipv4Addr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),AF_INET6=>Ok(IpAddr::V6(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte))),_=>Err(Error::new("ADDRESS_FAMILY","Unsupported address family"))}}
pub fn luid(value:u64)->NET_LUID_LH{NET_LUID_LH{Value:value}}
pub fn alias_luid(name:&str)->Result<u64>{let mut l=NET_LUID_LH::default();if unsafe{ConvertInterfaceAliasToLuid(wide(name).as_ptr(),&mut l)}!=0{return Err(Error::new("TUN_NOT_READY","TUN adapter is not ready"));}Ok(unsafe{l.Value})}
pub fn guid(l:u64)->Result<GUID>{let mut g=GUID::default();if unsafe{ConvertInterfaceLuidToGuid(&luid(l),&mut g)}!=0{return Err(Error::new("INTERFACE_IDENTITY","Cannot resolve interface identity"));}Ok(g)}
/// Successful bounded enumeration distinguishes absent from a failed identity query.
/// Only the former can release a recovery journal without attempting further mutations.
pub fn interface_identity(l:u64)->Result<Option<String>>{unsafe{
 let mut table=std::ptr::null_mut();if GetIfTable2(&mut table)!=0||table.is_null(){return Err(Error::new("INTERFACE_IDENTITY","Cannot verify interface ownership"));}
 let count=(*table).NumEntries as usize;if count>65536{FreeMibTable(table.cast());return Err(Error::new("INTERFACE_IDENTITY","Cannot verify bounded interface table"));}
 let identity=std::slice::from_raw_parts((*table).Table.as_ptr(),count).iter().find(|r|r.InterfaceLuid.Value==l).map(|r|guid_text(r.InterfaceGuid));FreeMibTable(table.cast());Ok(identity)
}}
pub fn guid_text(g:GUID)->String{format!("{:08x}-{:04x}-{:04x}-{}",g.data1,g.data2,g.data3,hex::encode(g.data4))}
fn routes()->Result<Vec<MIB_IPFORWARD_ROW2>>{unsafe{let mut p=std::ptr::null_mut();if GetIpForwardTable2(AF_UNSPEC,&mut p)!=0||p.is_null(){return Err(Error::new("ROUTE_QUERY","Cannot query Windows routes"));}let n=(*p).NumEntries as usize;if n>65536{FreeMibTable(p.cast());return Err(Error::new("ROUTE_QUERY","Too many route entries"));}let rows=std::slice::from_raw_parts((*p).Table.as_ptr(),n).to_vec();FreeMibTable(p.cast());Ok(rows)}}
pub fn physical(exclude:u64)->Result<Physical>{unsafe{
 let rs=routes()?;let mut bytes=32768u32;let mut buffer=vec![0u64;(bytes as usize+7)/8];
 let mut rc=GetAdaptersAddresses(AF_UNSPEC as u32,GAA_FLAG_INCLUDE_GATEWAYS,std::ptr::null(),buffer.as_mut_ptr().cast(),&mut bytes);
 if rc==ERROR_BUFFER_OVERFLOW{if bytes>4*1024*1024{return Err(Error::new("ADAPTER_QUERY","Too many adapters"));}buffer=vec![0;(bytes as usize+7)/8];rc=GetAdaptersAddresses(AF_UNSPEC as u32,GAA_FLAG_INCLUDE_GATEWAYS,std::ptr::null(),buffer.as_mut_ptr().cast(),&mut bytes);}
 if rc!=0{return Err(Error::new("ADAPTER_QUERY","Cannot query physical network adapters"));}
 let mut a=buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();let mut adapters=Vec::new();let mut count=0;
 while !a.is_null(){count+=1;if count>1024{return Err(Error::new("ADAPTER_QUERY","Invalid adapter list"));}let v=&*a;
  if v.Luid.Value!=exclude&&v.OperStatus==IfOperStatusUp&&v.IfType!=IF_TYPE_SOFTWARE_LOOPBACK&&v.IfType!=IF_TYPE_TUNNEL&&v.TunnelType==TUNNEL_TYPE_NONE{
   // Refuse unknown virtual VPN defaults instead of selecting them as a physical escape.
   let mut row=MIB_IF_ROW2::default();row.InterfaceLuid=v.Luid;
   if GetIfEntry2(&mut row)==0 && row.InterfaceAndOperStatusFlags._bitfield & 1 !=0 {adapters.push(a);}
  }a=v.Next;
 }
 let mut selected=[None,None];let mut details=Vec::new();let mut dns=Vec::new();
 for (family,slot) in [(AF_INET,0usize),(AF_INET6,1usize)]{
  let mut choices:Vec<(u32,u32,*const IP_ADAPTER_ADDRESSES_LH,String)>=Vec::new();
  for &a in &adapters{let a=&*a;let index=if family==AF_INET{a.Anonymous1.Anonymous.IfIndex}else{a.Ipv6IfIndex};let metric=if family==AF_INET{a.Ipv4Metric}else{a.Ipv6Metric};
   for r in &rs{if r.DestinationPrefix.Prefix.si_family==family&&r.DestinationPrefix.PrefixLength==0&&r.InterfaceLuid.Value==a.Luid.Value&&index!=0{choices.push((r.Metric.saturating_add(metric),index,a as *const _,ip(&r.NextHop)?.to_string()));}}
  }
  choices.sort_by_key(|v|v.0);if let Some((metric,index,a,hop))=choices.first(){selected[slot]=Some(*index);details.push(format!("{family}:{index}:{hop}:{metric}"));let mut d=(**a).FirstDnsServerAddress;let mut n=0;
   while !d.is_null(){n+=1;if n>64{return Err(Error::new("DNS_QUERY","Invalid DNS server list"));}let v=&*d;if !v.Address.lpSockaddr.is_null(){let p=v.Address.lpSockaddr.cast::<SOCKADDR_INET>();let s=ip(&*p)?.to_string();if !dns.contains(&s){dns.push(s);}}d=v.Next;}
  }
 }
 let dns=crate::service_protocol::physical_dns(dns)?;
 details.extend(dns.clone());let fingerprint=hex::encode(Sha256::digest(details.join("|").as_bytes()));
 let p=Physical{ipv4_if_index:selected[0],ipv6_if_index:selected[1],bootstrap_dns:dns,fingerprint};p.validate()?;Ok(p)
}}
fn route_row(r:&Route)->Result<MIB_IPFORWARD_ROW2>{let ip:std::net::IpAddr=r.destination.parse().map_err(|_|Error::new("ROUTE_INVALID","Invalid journal route"))?;let mut row=MIB_IPFORWARD_ROW2::default();unsafe{InitializeIpForwardEntry(&mut row);}row.InterfaceLuid=luid(r.luid);row.DestinationPrefix.Prefix=sockaddr(ip);row.DestinationPrefix.PrefixLength=r.prefix;row.NextHop=sockaddr(if ip.is_ipv4(){"0.0.0.0".parse().unwrap()}else{"::".parse().unwrap()});row.Metric=r.metric;row.Protocol=r.protocol;Ok(row)}
pub fn add_route(r:&Route)->Result<()>{let row=route_row(r)?;if unsafe{CreateIpForwardEntry2(&row)}!=0{return Err(Error::new("ROUTE_CREATE","Cannot create owned TUN route"));}Ok(())}
pub fn remove_route(r:&Route)->Result<()>{let mut row=route_row(r)?;let rc=unsafe{GetIpForwardEntry2(&mut row)};if rc==ERROR_NOT_FOUND{return Ok(());}if rc!=0{return Err(Error::new("ROUTE_QUERY","Cannot verify owned route"));}if row.Metric==r.metric&&row.Protocol==r.protocol{let rc=unsafe{DeleteIpForwardEntry2(&row)};if rc!=0&&rc!=ERROR_NOT_FOUND{return Err(Error::new("ROUTE_DELETE","Cannot remove owned TUN route"));}}Ok(())}
pub fn no_conflicting_host_dns(dns:&[String])->Result<()>{for r in routes()?{let a=unsafe{ip(&r.DestinationPrefix.Prefix)}?;if dns.contains(&a.to_string())&&r.DestinationPrefix.PrefixLength==if a.is_ipv4(){32}else{128}{return Err(Error::new("DNS_ROUTE_CONFLICT","A pre-existing host DNS route cannot be overridden"));}}Ok(())}
fn address_row(a:&Address)->Result<MIB_UNICASTIPADDRESS_ROW>{let mut row=MIB_UNICASTIPADDRESS_ROW::default();unsafe{InitializeUnicastIpAddressEntry(&mut row);}row.InterfaceLuid=luid(a.luid);row.Address=sockaddr(a.address.parse().map_err(|_|Error::new("ADDRESS_INVALID","Invalid journal address"))?);row.OnLinkPrefixLength=a.prefix;row.PrefixOrigin=IpPrefixOriginManual;row.SuffixOrigin=IpSuffixOriginManual;row.DadState=IpDadStatePreferred;row.SkipAsSource=false;Ok(row)}
pub fn add_address(a:&Address)->Result<()>{let row=address_row(a)?;if unsafe{CreateUnicastIpAddressEntry(&row)}!=0{return Err(Error::new("ADDRESS_CREATE","Cannot assign owned TUN address"));}Ok(())}
pub fn remove_address(a:&Address)->Result<()>{let mut row=address_row(a)?;let rc=unsafe{GetUnicastIpAddressEntry(&mut row)};if rc==ERROR_NOT_FOUND{return Ok(());}if rc!=0{return Err(Error::new("ADDRESS_QUERY","Cannot verify owned TUN address"));}if row.OnLinkPrefixLength==a.prefix&&row.PrefixOrigin==IpPrefixOriginManual{let rc=unsafe{DeleteUnicastIpAddressEntry(&row)};if rc!=0&&rc!=ERROR_NOT_FOUND{return Err(Error::new("ADDRESS_DELETE","Cannot remove owned TUN address"));}}Ok(())}
pub(super) fn interface_snapshot(l:u64,family:u16)->std::result::Result<(u64,IfSettings),u32>{let mut r=MIB_IPINTERFACE_ROW::default();r.Family=family;r.InterfaceLuid=luid(l);let rc=unsafe{GetIpInterfaceEntry(&mut r)};if rc!=0{return Err(rc);}Ok((unsafe{r.InterfaceLuid.Value},IfSettings{family:r.Family,mtu:r.NlMtu,metric:r.Metric,automatic_metric:r.UseAutomaticMetric,dad_transmits:r.DadTransmits}))}
pub fn interface(l:u64,family:u16)->Result<IfSettings>{interface_snapshot(l,family).map(|(_,s)|s).map_err(|_|Error::new("INTERFACE_QUERY","Cannot query TUN interface settings"))}
pub fn set_interface(l:u64,s:&IfSettings)->Result<()>{let mut r=MIB_IPINTERFACE_ROW::default();r.Family=s.family;r.InterfaceLuid=luid(l);if unsafe{GetIpInterfaceEntry(&mut r)}!=0{return Err(Error::new("INTERFACE_QUERY","Cannot query TUN interface"));}r.NlMtu=s.mtu;r.Metric=s.metric;r.UseAutomaticMetric=s.automatic_metric;r.DadTransmits=s.dad_transmits;r.SitePrefixLength=0;if unsafe{SetIpInterfaceEntry(&mut r)}!=0{return Err(Error::new("INTERFACE_SET","Cannot configure TUN interface"));}Ok(())}
pub fn dns(l:u64)->Result<Option<String>>{let mut s=DNS_INTERFACE_SETTINGS::default();s.Version=DNS_INTERFACE_SETTINGS_VERSION1;let rc=unsafe{GetInterfaceDnsSettings(guid(l)?,&mut s)};if rc!=0{return Err(Error::new("DNS_QUERY","Cannot query TUN DNS settings"));}let value=unsafe{string(s.NameServer)};unsafe{FreeInterfaceDnsSettings(&mut s);}Ok(if value.is_empty(){None}else{Some(value)})}
pub fn set_dns(l:u64,value:&Option<String>)->Result<()>{let mut p=wide(value.as_deref().unwrap_or(""));let mut s=DNS_INTERFACE_SETTINGS::default();s.Version=DNS_INTERFACE_SETTINGS_VERSION1;s.Flags=DNS_SETTING_NAMESERVER as u64;s.NameServer=p.as_mut_ptr();if unsafe{SetInterfaceDnsSettings(guid(l)?,&s)}!=0{return Err(Error::new("DNS_SET","Cannot configure TUN DNS settings"));}Ok(())}
