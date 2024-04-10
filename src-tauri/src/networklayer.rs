use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::{ipv4::Ipv4Packet,ipv6::Ipv6Packet};

use crate::other::UndecodeProtocal;
use crate::transformlayer::{IcmpMessage, Icmpv6Message, TcpMessage, TransformLayer, UdpMessage};

#[derive(Clone, serde::Serialize)]
pub enum NetworkLayer {
    Ipv4(Ipv4Message),
    Ipv6(Ipv6Message),
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct Ipv4Message{
    ttl:u8,
    // Time-to-live
    version:u8,
    // 协议版本
    header_length:u8,
    // 头部长度
    dscp:u8,
    //  Differentiated Services Code Point
    ecn:u8,
    // Explicit Congestion Notification
    flags:u8,
    // 标志
    next_level_protocal:u8,
    // 下一级协议
    checksum:u16,
    // 校验和
    total_length:u16,
    // 总长度
    fragment_offset:u16,
    // 分段偏移
    identification:u16,
    // 标识符
    source:String,
    // 源IP地址
    destination_ip:String,
    // 目的IP地址
    options:Vec<u8>,//由前端进行解释
    // 可选参数
    payload:Vec<u8>
    // 有效负载
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct Ipv6Message{
    // 目的IP地址
    destination_ip:String,
    // 流标签
    flow_label:u32,
    // 跳数
    hop_limit:u8,
    // 负载长度
    payload_length:u16,
    // 源IP地址
    source_ip:String,
    // 流量类
    traffic_class:u8,
    // 版本
    version:u8,
    // 下一级协议
    next_level_protocal:u8,
    
    payload:Vec<u8>
    // 有效负载
}
impl NetworkLayer {
    pub(crate) fn next_layer(&self)->Result<TransformLayer,UndecodeProtocal>{
        match self {
            NetworkLayer::Ipv4(ipv4message) =>{
                ipv4message.next_layer()
            },
            NetworkLayer::Ipv6(ipv6message) =>{
                ipv6message.next_layer()
            }
        }
    }
    pub(crate) fn get_info(&self)->String{
        match self {
            NetworkLayer::Ipv4(ipv4message) =>{
                ipv4message.get_info()
            },
            NetworkLayer::Ipv6(ipv6message) =>{
                ipv6message.get_info()
            }
        }
    }
    pub(crate) fn get_source(&self)->String{
        match self {
            NetworkLayer::Ipv4(ipv4message) =>{
                ipv4message.get_source()
            },
            NetworkLayer::Ipv6(ipv6message) =>{
                ipv6message.get_source()
            }
        }
    }
    pub(crate) fn get_destination(&self)->String{
        match self {
            NetworkLayer::Ipv4(ipv4message) =>{
                ipv4message.get_destination()
            },
            NetworkLayer::Ipv6(ipv6message) =>{
                ipv6message.get_destination()
            }
        }
    }
}
impl Ipv4Message {
    pub(crate) fn from(packet:&Ipv4Packet) -> Self{
        Self{
            checksum:packet.get_checksum(),
            destination_ip:packet.get_destination().to_string(),
            dscp:packet.get_dscp(),
            ecn:packet.get_ecn(),
            flags:packet.get_flags(),
            fragment_offset:packet.get_fragment_offset(),
            header_length:packet.get_header_length(),
            identification:packet.get_identification(),
            options: packet.get_options_raw().to_vec(),
            source: packet.get_source().to_string(),
            total_length: packet.get_total_length(),
            ttl: packet.get_ttl(),
            version: packet.get_version(),
            payload:packet.payload().into(),
            next_level_protocal:packet.get_next_level_protocol().0
        }
    }
    pub(crate)fn next_layer(&self)->Result<TransformLayer,UndecodeProtocal>{
        let next_protocal = IpNextHeaderProtocol::new(self.next_level_protocal);
        match next_protocal {
            IpNextHeaderProtocols::Tcp =>{
                if let Some(tcppacket) = TcpPacket::new(self.payload.as_slice()){
                    Ok(TransformLayer::Tcp(TcpMessage::from(tcppacket)))
                }else {
                    Err(UndecodeProtocal { 
                        protocal_name: next_protocal.to_string(),
                        payload:self.payload.clone()
                    })
                }
            },
            IpNextHeaderProtocols::Udp =>{
                if let Some(udppacket) = UdpPacket::new(self.payload.as_slice()){
                    Ok(TransformLayer::Udp(UdpMessage::from(udppacket)))
                }else {
                    Err(UndecodeProtocal { 
                        protocal_name: next_protocal.to_string(),
                        payload:self.payload.clone()
                    })
                }
            },
            IpNextHeaderProtocols::Icmp =>{
                if let Some(icmppacket) = IcmpPacket::new(self.payload.as_slice()){
                    Ok(TransformLayer::Icmp(IcmpMessage::from(icmppacket)))
                }else {
                    Err(UndecodeProtocal { 
                        protocal_name: next_protocal.to_string(),
                        payload:self.payload.clone()
                    })
                }
            },
            IpNextHeaderProtocol(x) => {
                Err(UndecodeProtocal { protocal_name: IpNextHeaderProtocol(x).to_string(), payload: self.payload.clone() })
            }
        }
    }
    pub(crate) fn get_info(&self)->String{
        format!("IP: {} => IP:{}  Len:{} Identification:{} Offset:{}",self.source,self.destination_ip,self.total_length,self.identification,self.fragment_offset)
    }
    pub(crate) fn get_source(&self)->String{
        self.source.clone()
    }
    pub(crate) fn get_destination(&self)->String{
        self.destination_ip.clone()
    }
}
impl Ipv6Message {
    pub(crate) fn from(packet:&Ipv6Packet) -> Self{
        Self{
            destination_ip:packet.get_destination().to_string(),
            flow_label:packet.get_flow_label(),
            hop_limit:packet.get_hop_limit(),
            payload_length:packet.get_payload_length(),
            source_ip:packet.get_source().to_string(),
            traffic_class:packet.get_traffic_class(),
            version: packet.get_version(),
            next_level_protocal:packet.get_next_header().0,
            payload: packet.payload().to_vec(),
        }
    }
    fn next_layer(&self)->Result<TransformLayer,UndecodeProtocal>{
        let next_protocal = IpNextHeaderProtocol::new(self.next_level_protocal);
        match next_protocal {
            IpNextHeaderProtocols::Tcp =>{
                if let Some(tcppacket) = TcpPacket::new(self.payload.as_slice()){
                    Ok(TransformLayer::Tcp(TcpMessage::from(tcppacket)))
                }else {
                    Err(UndecodeProtocal { 
                        protocal_name: next_protocal.to_string(),
                        payload:self.payload.clone()
                    })
                }
            },
            IpNextHeaderProtocols::Udp =>{
                if let Some(udppacket) = UdpPacket::new(self.payload.as_slice()){
                    Ok(TransformLayer::Udp(UdpMessage::from(udppacket)))
                }else {
                    Err(UndecodeProtocal { 
                        protocal_name: next_protocal.to_string(),
                        payload:self.payload.clone()
                    })
                }
            },
            IpNextHeaderProtocols::Icmpv6 =>{
                if let Some(icmpv6packet) = Icmpv6Packet::new(self.payload.as_slice()){
                    Ok(TransformLayer::Icmpv6(Icmpv6Message::from(icmpv6packet)))
                }else {
                    Err(UndecodeProtocal { 
                        protocal_name: next_protocal.to_string(),
                        payload:self.payload.clone()
                    })
                }
            },
            IpNextHeaderProtocol(x) => {
                Err(UndecodeProtocal { protocal_name: IpNextHeaderProtocol(x).to_string(), payload: self.payload.clone() })
            }
        }
    }
    pub(crate) fn get_info(&self)->String{
        format!("IP: {} -> IP: {} PayloadLen:{} ",self.source_ip,self.destination_ip,self.payload_length)
    }
    pub(crate) fn get_source(&self)->String{
        self.source_ip.clone()
    }
    pub(crate) fn get_destination(&self)->String{
        self.destination_ip.clone()
    }
}