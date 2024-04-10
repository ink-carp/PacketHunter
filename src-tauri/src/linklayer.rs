use pcap::Linktype;
use pnet::{packet::{arp::{ArpHardwareType, ArpHardwareTypes, ArpOperations, ArpPacket}, ethernet::{EtherType, EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, ipv6::Ipv6Packet,vlan::VlanPacket, Packet}, util::MacAddr};

use crate::{networklayer::{Ipv4Message, Ipv6Message, NetworkLayer}, other::UndecodeProtocal, PacketOwned};
#[derive(Clone, serde::Serialize)]
pub enum LinkLayer{
    Ethernet(EthernetMessage),
    Vlan(VlanMessage),
    Arp(ArpMessage),
    Null(Box<[u8]>),
    // Usbpcap,
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct EthernetMessage{
    // 声明一个Box类型的[u8]数组,用于存储目的地址mac
    destination_mac:String,
    // 声明一个Box类型的[u8]数组,用于存储源地址mac
    source_mac:String,
    // 声明一个String类型的以太类型
    ether_type:String,
    // 声明一个u16类型的包大小
    packet_size:u16,
    // 声明一个字符串,用于存储目的地址mac的消息
    destination_mac_message:String,
    // 声明一个字符串,用于存储源地址mac的消息
    source_mac_message:String,
    // 声明一个Box类型的[u8]数组,用于存储负载
    payload:Vec<u8>,
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct VlanMessage{
    // 表示是否可以被丢弃
    drop_eligible_indicator:u8,
    // 表示设备类型
    ethertype:String,
    // 表示优先级码点
    priority_code_point:u8,
    // 表示虚拟局域网络标识符
    vlan_identifier:u16,
    // 表示负载
    payload:Option<EthernetMessage>,
}
#[derive(Clone, serde::Serialize)]
// 定义一个ArpMessage结构体,用于存储ARP消息
pub(crate) struct ArpMessage{
    // 硬件地址长度
    protocal_address_length:u8,
    // 硬件类型
    hradware_address_length:u8,
    // 硬件类型
    hardware_type:String,
    // 选项
    opretion:String,
    // 协议类型
    protocal_type:String,
    // 发送者硬件地址
    sender_hardware_addr:String,
    // 发送者协议地址
    sender_protocal_address:String,
    // 目标硬件地址
    target_hardware_addr:String,
    // 目标协议地址
    target_protocal_address:String,
    target_mac_type:String
}
impl LinkLayer {
    pub(crate) fn from(raw:&PacketOwned,linktype:Linktype)->Result<Self,UndecodeProtocal>{
        match linktype {
            Linktype::ETHERNET=> {
                if let Some(ethernetpacket) = EthernetPacket::new(&raw.data){
                    if ethernetpacket.get_ethertype() == EtherTypes::Arp{
                        if let Some(arp) = ArpPacket::new(ethernetpacket.payload()) {
                            Ok(LinkLayer::Arp(ArpMessage::from(arp,ethernetpacket.get_destination())))
                        }else {
                            Err(UndecodeProtocal { protocal_name: ethernetpacket.get_ethertype().to_string(), payload: ethernetpacket.payload().into() })
                        }
                    }else {
                        Ok(LinkLayer::Ethernet(EthernetMessage::from(ethernetpacket)))
                    }
                }else {
                    Err(UndecodeProtocal { protocal_name: linktype.get_name().unwrap(), payload: raw.data.to_vec() })
                }
            },
            Linktype::NULL => {
                Ok(LinkLayer::Null(raw.data.clone()))
            },
            _ =>{
                if let Some(vlanpacket) = VlanPacket::new(&raw.data) {
                    Ok(LinkLayer::Vlan(VlanMessage::from(vlanpacket)))
                }
                else {
                    Err(UndecodeProtocal { protocal_name: linktype.get_name().unwrap_or("Unknown".to_string()), payload: raw.data.to_vec() })
                }
            }
        }
    }
    pub(crate) fn next_layer(&self)->Result<NetworkLayer,UndecodeProtocal>{
        match self{
            LinkLayer::Ethernet(ethernetmessage)=>{
                ethernetmessage.next_layer()
            },
            LinkLayer::Vlan(vlanmessage)=>{
                match &vlanmessage.payload {
                    Some(ethernetmessage) => {
                        ethernetmessage.next_layer()
                    },
                    None => {
                        Err(UndecodeProtocal{
                            protocal_name:"Vlan".to_string(),
                            payload:Vec::new(),
                        })
                    }
                }
            },
            LinkLayer::Null(raw) =>{
                null_to_next(raw)
            },
            //Arp没有下一层
            LinkLayer::Arp(_) =>{
                Err(UndecodeProtocal{
                    protocal_name:"Arp".to_string(),
                    payload:Vec::new(),
                })
            },
            //Usbpcap没有下一层
            _ => {
                Err(UndecodeProtocal{
                    protocal_name:"UsbPcap".to_string(),
                    payload:Vec::new(),
                })
            }
        }
    }
    // pub(crate) fn get_protocal_name(&self)->String{
    //     match self {
    //         LinkLayer::Arp(_) => "Arp".to_string(),
    //         LinkLayer::Ethernet(_) => "Ethernet".to_string(),
    //         LinkLayer::Vlan(_) => "Vlan".to_string(),
    //         LinkLayer::Null(_) => "Null".to_string(),
    //         LinkLayer::Usbpcap => "UsbPcap".to_string(),
    //     }
    // }
    pub(crate) fn get_source(&self)->String{
        match self {
            LinkLayer::Arp(arpmessage) => arpmessage.sender_hardware_addr.clone(),
            LinkLayer::Ethernet(ethernetmessage) => ethernetmessage.source_mac.clone(),
            LinkLayer::Vlan(vlanmessage) => match &vlanmessage.payload {
                Some(ether) => {ether.source_mac.clone()},
                None => {"Unknown".to_string()}
            },
            LinkLayer::Null(_) => "".to_string(),
            // LinkLayer::Usbpcap => "".to_string(),
        }
    }
    pub(crate) fn get_destination(&self)->String{
        match self {
            LinkLayer::Arp(arpmessage) => if arpmessage.opretion.eq_ignore_ascii_case("request"){
                arpmessage.target_mac_type.clone()
            }else{
                arpmessage.target_hardware_addr.clone()
            },
            LinkLayer::Ethernet(ethernetmessage) => ethernetmessage.destination_mac.clone(),
            LinkLayer::Vlan(vlanmessage) => match &vlanmessage.payload {
                Some(ether) => {ether.destination_mac.clone()},
                None => {"Unknown".to_string()}
            },
            LinkLayer::Null(_) => "".to_string(),
            // LinkLayer::Usbpcap => "".to_string(),
        }
    }
    pub fn get_info(&self)->String{
        match self {
            LinkLayer::Arp(arpmessage) => arpmessage.get_info(),
            LinkLayer::Ethernet(ethernetmessage) => ethernetmessage.get_info(),
            LinkLayer::Vlan(vlanmessage) =>vlanmessage.get_info(),
            LinkLayer::Null(_) => format!("Null packet Cannot know next leavl protocal"),
            // LinkLayer::Usbpcap => "Usbpcap".to_string(),
        }
    }
    pub fn get_payload(&self)->&[u8]{
        match self {
            LinkLayer::Arp(arpmessage) => arpmessage.target_protocal_address.as_bytes(),
            LinkLayer::Ethernet(ethernetmessage) => &ethernetmessage.payload,
            LinkLayer::Vlan(vlanmessage) => match &vlanmessage.payload {
                Some(ether) => {&ether.payload},
                None => &[0u8],
            },
            LinkLayer::Null(raw) => &raw,
            // LinkLayer::Usbpcap => &[0u8],
        }
    
    }
}

impl EthernetMessage {
    fn from(packet:EthernetPacket)->EthernetMessage{
        let mut dest_message = String::new();
            let mut src_message = String::new();
            let dest_mac = packet.get_destination();
            let src_mac = packet.get_source();
            if dest_mac.is_broadcast() {
                dest_message.push_str("广播地址");
            }
            if dest_mac.is_local(){
                dest_message.push_str(" 本地地址");
            }
            if dest_mac.is_multicast(){
                dest_message.push_str(" 多播地址");
            }
            if dest_mac.is_unicast(){
                dest_message.push_str(" 单播地址");
            }
            if dest_mac.is_universal(){
                dest_message.push_str(" 通用地址");
            }
            if dest_mac.is_zero(){
                dest_message.push_str(" 空地址");
            }
            if src_mac.is_broadcast() {
                src_message.push_str("广播地址");
            }
            if src_mac.is_local(){
                src_message.push_str(" 本地地址");
            }
            if src_mac.is_multicast(){
                src_message.push_str(" 多播地址");
            }
            if src_mac.is_unicast(){
                src_message.push_str(" 单播地址");
            }
            if src_mac.is_universal(){
                src_message.push_str(" 通用地址");
            }
            if src_mac.is_zero(){
                src_message.push_str(" 空地址");
            }
            EthernetMessage { 
                destination_mac: dest_mac.to_string(), 
                source_mac: src_mac.to_string(), 
                ether_type: packet.get_ethertype().to_string(), 
                packet_size:packet.packet().len() as u16,
                destination_mac_message:dest_message, 
                source_mac_message: src_message,
                payload:packet.payload().into()
            }
    }
    fn next_layer(&self)->Result<NetworkLayer,UndecodeProtocal>{
        if self.ether_type == "Ipv4" {
            if let Some(packet) = Ipv4Packet::new(&self.payload) {
                Ok(NetworkLayer::Ipv4(Ipv4Message::from(&packet)))
            }else {
                Err(UndecodeProtocal { protocal_name: EtherTypes::Ipv4.to_string(), payload: self.payload.clone() })
            }
        }else if(self.ether_type == "Ipv6"){
            if let Some(packet) = Ipv6Packet::new(&self.payload) {
                Ok(NetworkLayer::Ipv6(Ipv6Message::from(&packet)))
            }else {
                Err(UndecodeProtocal { protocal_name: EtherTypes::Ipv6.to_string(), payload: self.payload.clone()})
            }
        }else {
            Err(UndecodeProtocal{
                //pnet的ethertype不足以判断所有类型
                protocal_name:self.ether_type.clone(),
                payload:self.payload.clone(),
            })
        }
        // match EtherType::new(self.ether_type) {
        //     EtherTypes::Ipv4 => {
        //         if let Some(packet) = Ipv4Packet::new(&self.payload) {
        //             Ok(NetworkLayer::Ipv4(Ipv4Message::from(&packet)))
        //         }else {
        //             Err(UndecodeProtocal { protocal_name: EtherTypes::Ipv4.to_string(), payload: self.payload.clone() })
        //         }
        //     },
        //     EtherTypes::Ipv6 => {
        //         if let Some(packet) = Ipv6Packet::new(&self.payload) {
        //             Ok(NetworkLayer::Ipv6(Ipv6Message::from(&packet)))
        //         }else {
        //             Err(UndecodeProtocal { protocal_name: EtherTypes::Ipv6.to_string(), payload: self.payload.clone()})
        //         }
        //     },
        //     other => {
        //         Err(UndecodeProtocal{
        //             //pnet的ethertype不足以判断所有类型
        //             protocal_name:pcap::Linktype(other.0 as i32).get_name().unwrap_or("Unknown".to_string()),
        //             payload:self.payload.clone(),
        //         })
        //     }
        // }
    }
    fn get_info(&self)->String{
        format!("Ethenet from {} to {} ,type {} to {}",self.source_mac,self.destination_mac,self.source_mac_message,self.destination_mac_message)
    }
}

impl VlanMessage {
    fn from(packet:VlanPacket)->VlanMessage{
        VlanMessage{
            drop_eligible_indicator:packet.get_drop_eligible_indicator(),
            ethertype:packet.get_ethertype().to_string(),
            priority_code_point:packet.get_priority_code_point().0,
            vlan_identifier:packet.get_vlan_identifier(),
            payload:EthernetPacket::new(packet.payload()).map(EthernetMessage::from)
        }
    }
    fn get_info(&self)->String{
        match &self.payload {
            Some(ether) => {
                ether.get_info()
            },
            None => {
                "Vlan without Unknown Payload!".to_string()
            }
        }
    }
}
impl ArpMessage {
    fn from(packet:ArpPacket,target_mac:MacAddr)->ArpMessage{
        let target_mac_type = if target_mac.is_broadcast() {
            "Broadcast".to_string()
        }else if target_mac.is_multicast() {
            "Multicast".to_string()
        }else if target_mac.is_local(){
            "Local".to_string()
        }else if target_mac.is_unicast(){
            "Unicast".to_string()
        }else if target_mac.is_universal(){
            "Universal".to_string()
        }else{
            "Zero".to_string()
        };
        ArpMessage { 
            hardware_type: match packet.get_hardware_type() {
                ArpHardwareTypes::Ethernet => "Ethernet".to_string(),
                ArpHardwareType(x) => format!("Unknown Hardware code {x}"),
            }, 
            hradware_address_length: packet.get_hw_addr_len(), 
            opretion: match packet.get_operation() {
                ArpOperations::Reply => "Reply".to_string(),
                ArpOperations::Request => "Request".to_string(),
                _ => "Unknown".to_string(),
            }, 
            protocal_address_length:packet.get_proto_addr_len(), 
            protocal_type: packet.get_protocol_type().to_string(), 
            sender_hardware_addr:packet.get_sender_hw_addr().to_string(), 
            sender_protocal_address:packet.get_sender_proto_addr().to_string(), 
            target_hardware_addr: packet.get_target_hw_addr().to_string(), 
            target_protocal_address: packet.get_target_proto_addr().to_string(),
            target_mac_type
        }
    }
    fn get_info(&self)->String{
        format!("{} {} for {}",self.sender_protocal_address,self.opretion,self.target_protocal_address)
    }
}
fn null_to_next(raw:&Box<[u8]>)->Result<NetworkLayer,UndecodeProtocal>{
    if raw[0] == 2{
        if let Some(ipv4) = Ipv4Packet::new(&raw[4..]) {
            Ok(NetworkLayer::Ipv4(Ipv4Message::from(&ipv4)))
        }else{
            Err(UndecodeProtocal{
                protocal_name:"Ipv4".to_string(),
                payload:Vec::new(),
            })
        }
    }else if raw[0] == 24 || raw[0] == 28 || raw[0] == 30{
        if let Some(ipv6) = Ipv6Packet::new(raw){
            Ok(NetworkLayer::Ipv6(Ipv6Message::from(&ipv6)))
        }else{
            Err(UndecodeProtocal{
                protocal_name:"Ipv6".to_string(),
                payload:Vec::new(),
            })
        }
    }else if raw[0] == 7{
        Err(UndecodeProtocal{
            protocal_name:"OSI".to_string(),
            payload:Vec::new(),
        })
    }else if raw[3] == 23 {
        Err(UndecodeProtocal{
            protocal_name:"IPX".to_string(),
            payload:Vec::new(),
        })
    }else {
        Err(UndecodeProtocal{
            protocal_name:format!("Null code:{:?}",&raw[0..4]),
            payload:Vec::new(),
        })
    }
}