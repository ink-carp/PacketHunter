use pcap::{ConnectionStatus, Device, Linktype, PacketCodec, PacketHeader};
use pnet::packet::ethernet::EtherTypes;
use std::time::{SystemTime, Duration};
use chrono::{DateTime, Local};
use crate::{ info_linklayer, info_netlayer, info_translayer, parse_linklayer, parse_netlayer, parse_translayer};

pub(crate) trait HeaderFunc {
    fn get_source(&self) -> String;
    fn get_destination(&self) -> String;
    fn get_info(&self) -> String;
    fn get_finalprotocal(&self) -> String;
}
#[derive(Clone, serde::Serialize)]
pub struct PacketInfo{
    pub(crate) index:u32,
    pub(crate) source:String,
    pub(crate) destination:String,
    pub(crate) len:u32,
    pub(crate) time:String,
    pub(crate) finalprotocal:String,
    pub(crate) info:String,
}
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>,
}
/// Simple codec that tranform [`pcap::Packet`] into [`PacketOwned`]
#[derive(Clone, serde::Serialize)]
pub struct SimpleDevice{
    connected:bool,
    wireless:bool,
    name:String,
    description:String,
    ipv4:Option<String>,//string | null
    ipv6:Option<String>,
}
//-------------------------------------
#[derive(Clone, serde::Serialize)]
pub struct Stream{
  pub name:String,
  pub receive:u32,
  pub drop:u32,
}
pub struct Codec;

pub struct DeviceGoodChecker;
impl DeviceGoodChecker {
    // 定义一个检查设备是否符合条件的闭包
    pub fn good(dev: &Device) -> bool {
        (!dev.addresses.is_empty() && dev.flags.is_up() && dev.flags.is_running() && dev.flags.connection_status == ConnectionStatus::Connected) ||
        (dev.flags.is_loopback()&&dev.flags.is_running())
    }
}
impl PacketInfo {
    pub(crate) fn by(&mut self,header:impl HeaderFunc){
        self.source = header.get_source();
        self.destination = header.get_destination();
        self.finalprotocal = header.get_finalprotocal();
        self.info = header.get_info();
    }
    pub(crate) fn change(&mut self,source:String,destination:String,finalprotocal:String,info:String){
        self.source = source;
        self.destination = destination;
        self.finalprotocal = finalprotocal;
        self.info = info;
    }
}
impl SimpleDevice {
    pub fn from(dev:&Device)->SimpleDevice{
        let ipv4 = dev.addresses.iter().find_map(|addr| {
            if addr.addr.is_ipv4() {
                Some(addr.addr.to_string())
            } else {
                None
            }
        });
        let ipv6 = dev.addresses.iter().find_map(|addr| {
            if addr.addr.is_ipv6() {
                Some(addr.addr.to_string())
            } else {
                None
            }
        });
        SimpleDevice{
            connected:DeviceGoodChecker::good(dev),
            wireless:dev.flags.is_wireless(),
            name:dev.name.clone(),
            description:dev.desc.clone().unwrap_or("Unknown Device".to_string()),
            ipv4,
            ipv6
        }
    }
    pub fn get_connected(&self)->bool{
        self.connected
    }
}
impl PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        PacketOwned {
            header: *packet.header,
            data: packet.data.into(),
        }
    }
}
//为数据包实现解析
impl PacketOwned {
    ///parse应该要能返回一个protocal栈
    ///将原始数据一层一层的解析
    pub fn parse(&self,linktype:&Linktype,index:u32)->Vec<Protocal>{
        let mut ret = Vec::<Protocal>::new();
        ret.push(Protocal{
            name:format!("Frame {index}"),
            header:vec![
                format!("Frame:{index}"),
                format!("{} bytes on wire ({} bits)",self.header.len,self.header.len*8),
                format!("{} bytes captured ({} bits)",self.header.caplen,self.header.caplen*8),
                format!("Encapsulation type: {}",linktype.get_name().unwrap_or("Unknown".to_string())),
                format!("Arrival Time: {}",timeval_to_china_time(self.header.ts.tv_sec, self.header.ts.tv_usec)),
                ],
            payload:Some(self.data.to_vec())
        });
        if let Some((et,payload)) = parse_linklayer(&self.data,linktype,&mut ret){
            let trans;
            if *linktype == Linktype::NULL{
                trans = parse_netlayer(payload[0], payload[4..].to_vec(),&mut ret);
            }else if et == EtherTypes::Ipv4 {
                trans = parse_netlayer(2, payload,&mut ret);
            }
            else if et == EtherTypes::Ipv6{
                trans = parse_netlayer(24, payload,&mut ret);
            }else {
                ret.push(Protocal{
                    name:format!("{}",et),
                    header:vec![format!("协议 {} 暂不支持解析！",et)],
                    payload:Some(payload)
                });
                trans = None;
            }
            if let Some((next,payload)) = trans {
                parse_translayer(next, payload, &mut ret);
            }
        }
        ret
    }
    pub fn get_info(&self,linktype:&Linktype,index:u32)->PacketInfo{
        let mut info = PacketInfo{
            index:0,
            source:"".to_string(),
            destination:"".to_string(),
            len:0,
            time:"".to_string(),
            finalprotocal:"".to_string(),
            info:"".to_string()
        };
        let mut net = None;
        if let Some((et,payload)) = info_linklayer(&self.data,linktype,&mut info){
            if *linktype == Linktype::NULL{
                net = info_netlayer(payload[0], payload[4..].to_vec(),&mut info);
            }else if et == EtherTypes::Ipv4 {
                net = info_netlayer(2, payload,&mut info);
            }
            else if et == EtherTypes::Ipv6{
                net = info_netlayer(24, payload,&mut info);
            }else {
                //不关心其他协议
                net = None;
            }
        }
        if let Some((next,payload)) = net {
            info_translayer(next, payload,&mut info);
        }
        //最后添加数据报头信息
        info.index = index;
        info.len = self.header.len;
        info.time = timeval_to_china_time(self.header.ts.tv_sec, self.header.ts.tv_usec);
        info
    }
}
#[derive(Clone, serde::Serialize)]
pub struct Protocal{
    pub(crate) name:String,
    pub(crate) header:Vec<String>,
    pub(crate) payload:Option<Vec<u8>>
}
impl Protocal {
    pub fn get_name(&self)->String{
        self.name.clone()
    }
    pub fn get_header(&self)->Vec<String>{
        self.header.clone()
    }
    pub fn get_payload(&self)->Option<Vec<u8>>{
        self.payload.clone()
    }
}
fn timeval_to_china_time(tv_sec:i32,tv_usec:i32) -> String {
    // 计算时间戳，tv_sec 秒数 + tv_usec 微秒数
    let timestamp = tv_sec as u64 * 1_000 + tv_usec as u64 / 1_000;

    // 将时间戳转换为 SystemTime
    let system_time = SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp);

    // 将 SystemTime 转换为本地时间
    
    DateTime::<Local>::from(system_time).to_string()
}