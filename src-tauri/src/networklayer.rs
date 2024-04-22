use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::Packet;
use pnet::packet::{ipv4::Ipv4Packet,ipv6::Ipv6Packet};

use crate::tools::{HeaderFunc, Protocal};
use crate::info::HeaderInfo;


pub(crate) fn parse_netlayer(code:u8,row:Vec<u8>,protocals:&mut Vec<Protocal>)->Option<(IpNextHeaderProtocol,Vec<u8>)>{
    if code == 2{
        if let Some(ipv4) = Ipv4Packet::new(&row){
            protocals.push(Protocal{
                name:"IPv4".to_string(),
                header:Ipv4Header::from(&ipv4).parsr2vec(),
                payload:None
            });
            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp |
                IpNextHeaderProtocols::Udp |
                IpNextHeaderProtocols::Icmp =>{
                    Some((ipv4.get_next_level_protocol(),ipv4.payload().to_vec()))
                },
                next =>{
                    protocals.push(Protocal{
                        name:next.to_string(),
                        header:vec![format!("协议 {} 暂时无法解析",next)],
                        payload:Some(row)
                    });
                    None
                }
            }
        }else {
            protocals.push(Protocal{
                name:"IPv4".to_string(),
                header:vec!["数据包过小，无法解析为Ipv4数据包！".to_string()],
                payload:Some(row)
            });
            None
        }
    }else if code == 24 || code == 28 || code == 30{
        if let Some(ipv6) = Ipv6Packet::new(&row){
            protocals.push(Protocal{
                name:"IPv6".to_string(),
                header:Ipv6Header::from(&ipv6).parsr2vec(),
                payload:None
            });
            match ipv6.get_next_header() {
                IpNextHeaderProtocols::Tcp |
                IpNextHeaderProtocols::Udp |
                IpNextHeaderProtocols::Icmpv6 =>{
                    Some((ipv6.get_next_header(),ipv6.payload().to_vec()))
                },
                next =>{
                    protocals.push(Protocal{
                        name:next.to_string(),
                        header:vec![format!("协议 {} 暂时无法解析",next)],
                        payload:Some(row)
                    });
                    None
                }
            }
        }else {
            protocals.push(Protocal{
                name:"IPv6".to_string(),
                header:vec!["数据包过小，无法解析为Ipv6数据包！".to_string()],
                payload:Some(row)
            });
            None
        } 
    }else if code == 7{
        protocals.push(Protocal{
            name:"OSI".to_string(),
            header:vec!["OSI协议暂时无法解析".to_string()],
            payload:Some(row)
        });
        None
    }else if code == 23{
        protocals.push(Protocal{
            name:"IPX".to_string(),
            header:vec!["IPX协议暂时无法解析".to_string()],
            payload:Some(row)
        });
        None
    }else {
        protocals.push(Protocal{
            name:"未知的Null协议".to_string(),
            header:vec![format!("未知协议号:{}",code)],
            payload:Some(row)
        });
        None
    }
}

pub(crate) fn info_netlayer(code:u8,row:Vec<u8>,net_info:&mut HeaderInfo)->Option<(IpNextHeaderProtocol,Vec<u8>)>{
    if code == 2{
        net_info.set_protocal("IPv4".to_string());
        if let Some(ipv4) = Ipv4Packet::new(&row){
            let header = Ipv4Header::from(&ipv4);
            net_info.by(header);
            match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp |
                    IpNextHeaderProtocols::Udp |
                    IpNextHeaderProtocols::Icmp =>{
                    //可以解析为下一层协议
                    Some((ipv4.get_next_level_protocol(),ipv4.payload().to_vec()))
                },
                _ =>{
                    //不关心其下一层协议
                    None
                }
            }
        }else {
            //Info不变
           None
        }
    }else if code == 24 || code == 28 || code == 30{
        net_info.set_protocal("IPv6".to_string());
        if let Some(ipv6) = Ipv6Packet::new(&row){
            let header = Ipv6Header::from(&ipv6);
            net_info.by(header);
            match ipv6.get_next_header() {
                IpNextHeaderProtocols::Tcp |
                IpNextHeaderProtocols::Udp |
                IpNextHeaderProtocols::Icmpv6 =>{
                    Some((ipv6.get_next_header(),ipv6.payload().to_vec()))
                },
                _ =>{
                    //不关心其下一层协议
                    None
                }
            }
        }else {
            //Info不变
            None
        } 
    }else {
        //不关心其他协议
        None
    }
}
pub struct Ipv4Header{
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
}
pub struct Ipv6Header{
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
}
impl Ipv4Header{
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
            next_level_protocal:packet.get_next_level_protocol().0
        }
    }
    pub(crate) fn parsr2vec(&self)->Vec<String>{
        vec![
            format!("版本号: {}", self.version),
            format!("头部长度: {}", self.header_length),
            format!("DSCP: {}", self.dscp),
            format!("ECN: {}", self.ecn),
            format!("总长度: {}", self.total_length),
            format!("标识符: {}", self.identification),
            format!("标志: {}", self.flags),
            format!("分段偏移: {}", self.fragment_offset),
            format!("TTL: {}", self.ttl),
            format!("下一级协议: {}", self.next_level_protocal),
            format!("校验和: {}", self.checksum),
            format!("源IP地址: {}", self.source),
            format!("目的IP地址: {}", self.destination_ip),
            format!("可选参数: {:?}", self.options),
        ]
    }
}
impl HeaderFunc for Ipv4Header {
    fn get_info(&self)->String{
        format!("IP: {} => IP:{}  Len:{} Identification:{} Offset:{}",self.source,self.destination_ip,self.total_length,self.identification,self.fragment_offset)
    }
    
    fn get_source(&self) -> String {
        self.source.clone()
    }
    
    fn get_destination(&self) -> String {
        self.destination_ip.clone()
    }
    
}
impl Ipv6Header {
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
        }
    }
    pub(crate) fn parsr2vec(&self)->Vec<String>{
        vec![
            format!("版本号: {}", self.version),
            format!("流量类别: {}", self.traffic_class),
            format!("流标签: {}", self.flow_label),
            format!("负载长度: {}", self.payload_length),
            format!("下一级协议: {}", self.next_level_protocal),
            format!("跳数限制: {}", self.hop_limit),
            format!("源IP地址: {}", self.source_ip),
            format!("目的IP地址: {}", self.destination_ip),
            ]
    }
}
impl HeaderFunc for Ipv6Header {
    fn get_info(&self)->String{
        format!("IP: {} -> IP: {} PayloadLen:{} ",self.source_ip,self.destination_ip,self.payload_length)
    }
    
    fn get_source(&self) -> String {
        self.source_ip.clone()
    }
    
    fn get_destination(&self) -> String {
        self.destination_ip.clone()
    }
}