use pcap::{ConnectionStatus, Device, Linktype, PacketCodec, PacketHeader};
use std::time::{SystemTime, Duration};
use chrono::{DateTime, Local};
use crate::{linklayer::LinkLayer, networklayer::NetworkLayer, transformlayer::TransformLayer};
#[derive(Clone, serde::Serialize)]
pub struct UndecodeProtocal{
    pub(crate) protocal_name:String,
    pub(crate) payload:Vec<u8>,
}
#[derive(Clone, serde::Serialize)]
pub struct PacketInfo{
    index:u32,
    source:String,
    destination:String,
    len:u32,
    time:String,
    finalprotocal:String,
    info:String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
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
//------------------------------------
#[derive(Clone, serde::Serialize)]
pub struct Flow{
  pub nets:Vec<Stream>,
}
//-------------------------------------
#[derive(Clone, serde::Serialize)]
pub struct Stream{
  pub name:String,
  pub receive:u32,
  pub drop:u32,
}
pub struct DeviceGoodChecker;
pub struct Codec;
pub struct PacketDetail{
    pub(crate) packetinfo:PacketInfo,
    pub(crate) linklayer:Result<LinkLayer,UndecodeProtocal>,//linklayer一定存在
    pub(crate) networklayer:Option<Result<NetworkLayer,UndecodeProtocal>>,
    pub(crate) transportlayer:Option<Result<TransformLayer,UndecodeProtocal>>,
}














impl PacketDetail{
    pub fn from(packet:PacketOwned,index:usize,linktype:Linktype)->Self{
        let link = LinkLayer::from(&packet,linktype);
        let net;
        let trans;
        let fp;
        let info;
        let source;
        let destination;
        match &link {
            Ok(islink) => {
                match islink.next_layer() {
                    Ok(isnet) => {
                        source=isnet.get_source();
                        destination=isnet.get_destination();
                        match isnet.next_layer() {
                            Ok(istrans) => {
                                fp = istrans.get_protocal_name();
                                info = istrans.get_info();
                                net = Some(Ok(isnet));
                                trans = Some(Ok(istrans));
                            }
                            Err(un) => {
                                fp = un.protocal_name.clone();
                                info = isnet.get_info();
                                net = Some(Ok(isnet));
                                trans=Some(Err(un));
                            }
                        }
                    },
                    Err(un) => {
                        source=islink.get_source();
                        destination=islink.get_destination();
                        fp = un.protocal_name.clone();
                        info = islink.get_info();
                        net = Some(Err(un));
                        trans = None;
                    }
                }
            },
            Err(un) =>{
                source="Unknown".to_string();
                destination="Unknown".to_string();
                fp = un.protocal_name.clone();
                info = "数据包解析失败!".to_string();
                net = None;
                trans = None;
            }
        }
        let pi = PacketInfo{
            index:index as u32,
            len:packet.header.len,
            source,
            destination,
            time:timeval_to_china_time(packet.header.ts.tv_sec, packet.header.ts.tv_usec).to_string(),
            finalprotocal:fp,
            info,
        };
        Self { 
            packetinfo: pi, 
            linklayer: link, 
            networklayer: net, 
            transportlayer: trans 
        }
    }
    pub fn get_info(&self)->PacketInfo{
        self.packetinfo.clone()
    }
    pub fn get_linklayer(&self)->Result<LinkLayer, UndecodeProtocal>{
        self.linklayer.clone()
    }
    pub fn get_net_layer(&self)->Option<Result<NetworkLayer,UndecodeProtocal>>{
        self.networklayer.clone()
    }
    pub fn get_trans_layer(&self)->Option<Result<TransformLayer,UndecodeProtocal>>{
        self.transportlayer.clone()
    }
    pub fn get_payload(&self)->&[u8]{
        match &self.linklayer {
            Ok(link) => {
                link.get_payload()
            },
            Err(e) => {
                e.payload.as_slice()
            }
        }
    }
}
impl DeviceGoodChecker {
    // 定义一个检查设备是否符合条件的闭包
    pub fn good(&self, dev: &Device) -> bool {
        (!dev.addresses.is_empty() && dev.flags.is_up() && dev.flags.is_running() && dev.flags.connection_status == ConnectionStatus::Connected) ||
        (dev.flags.is_loopback()&&dev.flags.is_running())
    }
}
impl SimpleDevice {
    pub fn from(dev:Device)->SimpleDevice{
        let ipv4;
        let ipv6;
        match dev.addresses.len() {
            0 => {
                ipv4 = None;
                ipv6 = None;
            },
            1 => {
                ipv4 = Some(dev.addresses.first().unwrap().addr.to_string());
                ipv6 = None;
            },
            _ => {
                ipv4 = Some(dev.addresses.first().unwrap().addr.to_string());
            ipv6 = Some(dev.addresses.get(1).unwrap().addr.to_string());
            }
        }
        SimpleDevice{
            connected:(!dev.addresses.is_empty() && dev.flags.is_up() && dev.flags.is_running() && dev.flags.connection_status == ConnectionStatus::Connected) ||
            (dev.flags.is_loopback()&&dev.flags.is_running()),
            wireless:dev.flags.is_wireless(),
            name:dev.name,
            description:dev.desc.unwrap_or("Unknown Device".to_string()),
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
fn timeval_to_china_time(tv_sec:i32,tv_usec:i32) -> DateTime<Local> {
    // 计算时间戳，tv_sec 秒数 + tv_usec 微秒数
    let timestamp = tv_sec as u64 * 1_000 + tv_usec as u64 / 1_000;

    // 将时间戳转换为 SystemTime
    let system_time = SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp as u64);

    // 将 SystemTime 转换为本地时间
    let local_time = DateTime::<Local>::from(system_time);
    local_time
}