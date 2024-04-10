use pnet::packet::{icmp::{IcmpPacket, IcmpType, IcmpTypes}, icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types}, tcp::{TcpFlags, TcpPacket}, udp::{self, UdpPacket}, Packet};


#[derive(Clone, serde::Serialize)]
pub enum TransformLayer {
    Tcp(TcpMessage),
    Udp(UdpMessage),
    Icmp(IcmpMessage),
    Icmpv6(Icmpv6Message)
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct TcpMessage{
    acknownledgement:u32, // 确认号
    sequence:u32, // 序列号
    window:u16, // 窗口大小
    flags:u8, // 标志位
    payload:Vec<u8>, // 数据
    checksum:u16, // 校验和
    data_offset:u8, // 数据偏移
    reserved:u8, // 保留位
    source_port:u16, // 源端口
    urgent_pointer:u16, // 紧急指针
    destination_port:u16, // 目的端口
    //暂时不对option进行解释，由前端进行解释
    options:Vec<u8>, // 选项
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct UdpMessage{
    source_port:u16, // 源端口
    destination_port:u16, // 目的端口
    length:u16, // 长度
    checksum:u16, // 校验和
    payload:Vec<u8>, // 数据
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct IcmpMessage{
    icmp_type:u8, // ICMP类型
    icmp_code:u8, // ICMP代码
    checksum:u16, // 校验和
    data:Vec<u8>, // 数据
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct Icmpv6Message{
    icmpv6_type:u8, // ICMPv6类型
    icmpv6_code:u8, // ICMPv6代码
    checksum:u16, // 校验和
    data:Vec<u8>, // 数据
}

impl TransformLayer {
    pub(crate) fn get_protocal_name(&self)->String{
        match self {
            TransformLayer::Tcp(_) => "TCP".to_string(),
            TransformLayer::Udp(_) => "UDP".to_string(),
            TransformLayer::Icmp(_) => "ICMP".to_string(),
            TransformLayer::Icmpv6(_) => "ICMPv6".to_string(),
        }
    }
    pub(crate) fn get_info(&self)->String{
        match self {
            TransformLayer::Tcp(tcp) =>{
                tcp.get_info()
            },
            TransformLayer::Udp(udp) => {
                udp.get_info()
            },   
            TransformLayer::Icmp(icmp) =>{
                icmp.get_info()
            },
            TransformLayer::Icmpv6(icmpv6) =>{
                icmpv6.get_info()
            },
        }
    }
}
impl TcpMessage {
    pub(crate) fn from(packet:TcpPacket)->Self{
        Self { 
            acknownledgement: packet.get_acknowledgement(), 
            sequence: packet.get_sequence(), 
            window: packet.get_window(), 
            flags: packet.get_flags(), 
            payload: packet.payload().to_vec(), 
            checksum: packet.get_checksum(), 
            data_offset: packet.get_data_offset(), 
            reserved: packet.get_reserved(), 
            source_port: packet.get_source(), 
            urgent_pointer: packet.get_urgent_ptr(), 
            destination_port: packet.get_destination(), 
            options: packet.get_options_raw().to_vec()}
    }
    pub(crate) fn get_info(&self)->String{
        let mut flag = String::from(" ");
        if self.flags & TcpFlags::ACK != 0{
            flag.push_str("ACK ");
        }
        if self.flags & TcpFlags::CWR != 0{
            flag.push_str("CWR ");
        }
        if self.flags & TcpFlags::ECE != 0{
            flag.push_str("ECE ");
        }
        if self.flags & TcpFlags::FIN != 0{
            flag.push_str("FIN ");
        }
        if self.flags & TcpFlags::PSH != 0{
            flag.push_str("PSH ");
        }
        if self.flags & TcpFlags::RST != 0{
            flag.push_str("RST ");
        }
        if self.flags & TcpFlags::SYN != 0{
            flag.push_str("SYN ");
        }
        if self.flags & TcpFlags::URG != 0{
            flag.push_str("URG ");
        }
        format!("[{flag}] port:{} -> port:{} Seq={} Ack={} Win={} Len={}",self.source_port, self.destination_port,self.sequence, self.acknownledgement, self.window, self.payload.len())
    }
}
impl UdpMessage {
    pub(crate) fn from(packet:UdpPacket)->Self{
        Self { 
            source_port: packet.get_source(), 
            destination_port: packet.get_destination(), 
            length: packet.get_length(), 
            checksum: packet.get_checksum(), 
            payload: packet.payload().to_vec()
        }
    }
    pub(crate) fn get_info(&self)->String{
        format!("port:{} -> port:{} Len={}", self.source_port,self.destination_port,self.length)
    }
}
impl IcmpMessage {
    pub(crate) fn from(packet:IcmpPacket)->Self{
        Self { 
            icmp_type: packet.get_icmp_type().0, 
            checksum: packet.get_checksum(), 
            data:packet.payload().to_vec(),
            icmp_code: packet.get_icmp_code().0,
        }
    }
    pub fn type2string(&self)->String{
        match IcmpType::new(self.icmp_type) {
            IcmpTypes::AddressMaskReply => "AddressMaskReply".to_string(),
            IcmpTypes::AddressMaskRequest => "AddressMaskRequest".to_string(),
            IcmpTypes::DestinationUnreachable => "DestinationUnreachable".to_string(),
            IcmpTypes::EchoReply => "EchoReply".to_string(),
            IcmpTypes::EchoRequest => "EchoRequest".to_string(),
            IcmpTypes::InformationRequest => "InformationRequest".to_string(),
            IcmpTypes::InformationReply => "InformationReply".to_string(),
            IcmpTypes::ParameterProblem => "ParameterProblem".to_string(),
            IcmpTypes::RedirectMessage => "RedirectMessage".to_string(),
            IcmpTypes::RouterSolicitation => "RouterSolicitation".to_string(),
            IcmpTypes::RouterAdvertisement => "RouterAdvertisement".to_string(),
            IcmpTypes::Timestamp => "Timestamp".to_string(),
            IcmpTypes::TimestampReply => "TimestampReply".to_string(),
            IcmpTypes::SourceQuench => "SourceQuench".to_string(),
            IcmpTypes::TimeExceeded => "TimeExceeded".to_string(),
            IcmpTypes::Traceroute => "Traceroute".to_string(),
            _ => "Unknown".to_string(),
        }
    }
    pub(crate) fn get_info(&self)->String{
        format!("type:{} -> code:{}",self.type2string(),self.icmp_code)
    }
}
impl Icmpv6Message {
    pub(crate) fn from(packet:Icmpv6Packet)->Self{
        Self { 
            icmpv6_type: packet.get_icmpv6_type().0, 
            checksum: packet.get_checksum(), 
            data:packet.payload().to_vec(),
            icmpv6_code: packet.get_icmpv6_code().0,
        }
    }
    pub fn type2string(&self)->String{
        match Icmpv6Type(self.icmpv6_type) {
            Icmpv6Types::DestinationUnreachable => "DestinationUnreachable".to_string(),
            Icmpv6Types::PacketTooBig => "PacketTooBig".to_string(),
            Icmpv6Types::TimeExceeded => "TimeExceeded".to_string(),
            Icmpv6Types::ParameterProblem => "ParameterProblem".to_string(),
            Icmpv6Types::EchoRequest => "EchoRequest".to_string(),
            Icmpv6Types::EchoReply => "EchoReply".to_string(),
            Icmpv6Types::NeighborAdvert => "NeighborAdvert".to_string(),
            Icmpv6Types::NeighborSolicit => "NeighborSolicit".to_string(),
            Icmpv6Types::RouterAdvert => "RouterAdvert".to_string(),
            Icmpv6Types::RouterSolicit => "RouterSolicit".to_string(),
            Icmpv6Types::Redirect => "Redirect".to_string(),
            _ => "Unknown".to_string(),
        }
    }
    pub(crate) fn get_info(&self)->String{
        format!("type:{} -> code:{}",self.type2string(),self.icmpv6_code)
    }
}
    