use pnet::packet::{
    icmp::{IcmpPacket, IcmpType, IcmpTypes}, 
    icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types}, 
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, 
    tcp::{TcpFlags, TcpPacket}, udp::UdpPacket, Packet};
use crate::tools::{HeaderFunc, Protocal};
use crate::info::HeaderInfo;

pub(crate) fn parse_translayer(next:IpNextHeaderProtocol,row:Vec<u8>,protocals:&mut Vec<Protocal>){
    match next {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(&row) {
                let header = TcpHeader::from(&tcp);
                protocals.push(Protocal{
                    name:"TCP".to_string(),
                    header:header.parse2vec(),
                    payload:Some(tcp.payload().to_vec())
                });
            }else {
                protocals.push(Protocal{
                    name:"TCP".to_string(),
                    header:vec!["数据包过小，无法解析为TCP帧".to_string()],
                    payload:Some(row)
                });
            }
        },
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(&row) {
                let header = UdpHeader::from(&udp);
                protocals.push(Protocal{
                    name:"UDP".to_string(),
                    header:header.parse2vec(),
                    payload:Some(udp.payload().to_vec())
                });
            }else {
                protocals.push(Protocal{
                    name:"UDP".to_string(),
                    header:vec!["数据包过小，无法解析为UDP帧".to_string()],
                    payload:Some(row)
                });
            }
        },
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(&row) {
                let header = IcmpHeader::from(&icmp);
                protocals.push(Protocal{
                    name:"ICMP".to_string(),
                    header:header.parse2vec(),
                    payload:Some(icmp.payload().to_vec())
                });
            }else {
                protocals.push(Protocal{
                    name:"ICMP".to_string(),
                    header:vec!["数据包过小，无法解析为ICMP帧".to_string()],
                    payload:Some(row)
                });
            }
        },
        IpNextHeaderProtocols::Icmpv6 => {
            if let Some(icmpv6) = Icmpv6Packet::new(&row) {
                let header = Icmpv6Header::from(&icmpv6);
                protocals.push(Protocal{
                    name:"ICMPv6".to_string(),
                    header:header.parse2vec(),
                    payload:Some(icmpv6.payload().to_vec())
                });
            }else {
                protocals.push(Protocal{
                    name:"ICMPv6".to_string(),
                    header:vec!["数据包过小，无法解析为ICMPv6帧".to_string()],
                    payload:Some(row)
                });
            }
        },
        next =>{
            protocals.push(Protocal{
                name:next.to_string(),
                header:vec![format!("协议 [{}] 暂不支持解析！",next.to_string())],
                payload:Some(row)
            });
        }
    }
}
pub(crate) fn info_translayer(next:IpNextHeaderProtocol,row:Vec<u8>,trans_info:&mut HeaderInfo){
    trans_info.protocal = next.to_string();
    match next {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(&row) {
                let header = TcpHeader::from(&tcp);
                trans_info.by(header);
            }
            //不关心解析失败的情况
        },
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(&row) {
                let header = UdpHeader::from(&udp);
                trans_info.by(header);
            }
            //不关心解析失败的情况
        },
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(&row) {
                let header = IcmpHeader::from(&icmp);
                trans_info.by(header);
            }
            //不关心解析失败的情况
        },
        IpNextHeaderProtocols::Icmpv6 => {
            if let Some(icmpv6) = Icmpv6Packet::new(&row) {
                let header = Icmpv6Header::from(&icmpv6);
                trans_info.by(header);
            }
            //不关心解析失败的情况
        },
        _ =>{}
    }
}
pub struct TcpHeader{
    acknownledgement:u32, // 确认号
    sequence:u32, // 序列号
    window:u16, // 窗口大小
    flags:u8, // 标志位
    checksum:u16, // 校验和
    data_offset:u8, // 数据偏移
    reserved:u8, // 保留位
    source_port:u16, // 源端口
    urgent_pointer:u16, // 紧急指针
    destination_port:u16, // 目的端口
    //暂时不对option进行解释，由前端进行解释
    options:Vec<u8>, // 选项
    payload_size:usize,
}
pub struct UdpHeader{
    source_port:u16, // 源端口
    destination_port:u16, // 目的端口
    length:u16, // 长度
    checksum:u16, // 校验和
    payload_size:usize,
}
pub struct IcmpHeader{
    icmp_type:u8, // ICMP类型
    icmp_code:u8, // ICMP代码
    checksum:u16, // 校验和
    payload_size:usize,
}
pub struct Icmpv6Header{
    icmpv6_type:u8, // ICMPv6类型
    icmpv6_code:u8, // ICMPv6代码
    checksum:u16, // 校验和
    payload_size:usize,
}

impl TcpHeader {
    pub fn from(packet:&TcpPacket)->Self{
        Self { 
            acknownledgement: packet.get_acknowledgement(), 
            sequence: packet.get_sequence(), 
            window: packet.get_window(), 
            flags: packet.get_flags(), 
            checksum: packet.get_checksum(), 
            data_offset: packet.get_data_offset(), 
            reserved: packet.get_reserved(), 
            source_port: packet.get_source(), 
            urgent_pointer: packet.get_urgent_ptr(), 
            destination_port: packet.get_destination(), 
            options: packet.get_options_raw().to_vec(),
            payload_size: packet.payload().len(),
        }
    }
    pub(crate) fn parse2vec(&self) -> Vec<String> {
        vec![
            format!("源端口: {}", self.source_port),
            format!("目的端口: {}", self.destination_port),
            format!("序列号: {}", self.sequence),
            format!("确认号: {}", self.acknownledgement),
            format!("窗口大小: {}", self.window),
            format!("标志位: {}", self.flags),
            format!("校验和: {}", self.checksum),
            format!("数据偏移: {}", self.data_offset),
            format!("保留位: {}", self.reserved),
            format!("紧急指针: {}", self.urgent_pointer),
            format!("选项: {:?}", self.options),
            format!("负载大小: {}", self.payload_size),
        ]
    }
}
impl HeaderFunc for TcpHeader {
    fn get_info(&self)->String{
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
        format!("[{flag}] port:{} -> port:{} Seq={} Ack={} Win={} Len={}",self.source_port, self.destination_port,self.sequence, self.acknownledgement, self.window,self.payload_size)
    }
    fn get_source(&self) -> String {
        self.source_port.to_string()
    }
    fn get_destination(&self) -> String {
        self.destination_port.to_string()
    }
}
impl UdpHeader {
    pub fn from(packet:&UdpPacket)->Self{
        Self { 
            source_port: packet.get_source(), 
            destination_port: packet.get_destination(), 
            length: packet.get_length(), 
            checksum: packet.get_checksum(), 
            payload_size: packet.payload().len(),
        }
    }
    pub(super) fn parse2vec(&self) -> Vec<String> {
        vec![
            format!("源端口: {}", self.source_port),
            format!("目的端口: {}", self.destination_port),
            format!("长度: {}", self.length),
            format!("校验和: {}", self.checksum),
            format!("负载大小: {}", self.payload_size),
        ]
    }
}
impl HeaderFunc for UdpHeader {
    fn get_info(&self)->String{
        format!("port:{} -> port:{} Len={}", self.source_port,self.destination_port,self.length)
    }
    fn get_source(&self) -> String {
        self.source_port.to_string()
    }
    fn get_destination(&self) -> String {
        self.destination_port.to_string()
    }
}
impl IcmpHeader {
    pub fn from(packet:&IcmpPacket)->Self{
        Self { 
            icmp_type: packet.get_icmp_type().0, 
            checksum: packet.get_checksum(), 
            icmp_code: packet.get_icmp_code().0,
            payload_size: packet.payload().len(),
        }
    }
    fn type2string(&self)->String{
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
    pub(crate) fn parse2vec(&self) -> Vec<String> {
        vec![
            format!("类型: {}", self.icmp_type),
            format!("代码: {}", self.icmp_code),
            format!("校验和: {}", self.checksum),
            format!("负载大小: {}", self.payload_size),
        ]
    }
}
impl HeaderFunc for IcmpHeader {
    fn get_info(&self)->String{
        format!("type:{} -> code:{}",self.type2string(),self.icmp_code)
    }
    fn get_source(&self) -> String {
        "".to_string()
    }
    fn get_destination(&self) -> String {
        "".to_string()
    }
}
impl Icmpv6Header {
    pub fn from(packet:&Icmpv6Packet)->Self{
        Self { 
            icmpv6_type: packet.get_icmpv6_type().0, 
            checksum: packet.get_checksum(), 
            icmpv6_code: packet.get_icmpv6_code().0,
            payload_size: packet.payload().len(),
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
    pub(crate) fn parse2vec(&self) -> Vec<String> {
        vec![
            format!("类型: {}", self.icmpv6_type),
            format!("代码: {}", self.icmpv6_code),
            format!("校验和: {}", self.checksum),
            format!("负载大小: {}", self.payload_size),
        ]
    }
}
impl HeaderFunc for Icmpv6Header {
    fn get_info(&self)->String{
        format!("type:{} -> code:{}",self.type2string(),self.icmpv6_code)
    }
    fn get_source(&self) -> String {
        "".to_string()
    }
    fn get_destination(&self) -> String {
        "".to_string()
    }
}
    