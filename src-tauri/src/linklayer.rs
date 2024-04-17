use pcap::Linktype;
use pnet::packet::{arp::{ArpHardwareType, ArpHardwareTypes, ArpOperations, ArpPacket}, ethernet::{ EtherType, EtherTypes, EthernetPacket}, vlan::VlanPacket, Packet};
use crate::{other::{HeaderFunc, Protocal}, PacketInfo};
pub(crate) fn parse_linklayer(row:&[u8],linktype:&Linktype,protocals:&mut Vec<Protocal>)->Option<(EtherType,Vec<u8>)>{
    match *linktype{
        Linktype::ETHERNET =>{
            if let Some(packet) = EthernetPacket::new(row){
                handle_ethertype(packet.get_ethertype(), packet, protocals)
            }else {
                protocals.push(
                    Protocal { 
                        name: "Ethernet".to_string(),
                        header: vec!["数据包过小，无法解析为以太网帧！".to_string()],
                        payload:Some(row.to_vec()) }
                    );
                None
            }
        },
        Linktype::NULL => {
            protocals.push(Protocal { 
                name: "Null".to_string(),
                header: vec![],
                payload:None
             });
            None
        },
        lt =>{
            protocals.push(Protocal { 
                name: lt.get_name().unwrap_or(format!("链路类型 [{}]",lt.0)), 
                header: vec![format!("抱歉，链路类型 [{}] [{}] 暂时无法解析!",lt.get_name().unwrap_or(lt.0.to_string()),lt.get_description().unwrap_or("未知链路类型".to_string()))],
                payload:Some(row.to_vec())
            });
            None
        }
    }
}
pub(crate) fn info_linklayer(row:&[u8],linktype:&Linktype,info:&mut PacketInfo)->Option<(EtherType,Vec<u8>)>{
    match *linktype{
        Linktype::ETHERNET =>{
            if let Some(packet) = EthernetPacket::new(row){
                let header = EthernetHeader::from(&packet);
                info.by(header);
                info_ethertype(packet.get_ethertype(), packet,info)
            }else {
                info.change(
                    "Unknown".to_string(),
                    "Unknown".to_string(),
                    "Ethernet".to_string(),
                    "数据包太小，无法解析为以太网帧！".to_string(),
                );
                None
            }
        },
        Linktype::NULL => {
            info.change(
                "Unkown".to_string(),
                "Unknown".to_string(), 
                "Null".to_string(),
                "链路类型:Null".to_string(),
            );
            Some((EtherTypes::Ipv4,row.to_vec()))
        },
        lt =>{
            info.change(
                "Unknown".to_string(),
                "Unknown".to_string(),
                lt.get_name().unwrap_or(format!("链路类型 [{}]",lt.0)),
                format!("抱歉，链路类型 [{}] [{}] 暂时无法解析!",lt.get_name().unwrap_or(lt.0.to_string()),lt.get_description().unwrap_or("未知链路类型".to_string()))
            );
            None
        }
    }
}
/// 该函数只解析了ARP和VLAN帧头部信息
/// 并添加了以太网帧头部信息
fn handle_ethertype(ethertype:EtherType,packet: EthernetPacket,protocals:&mut Vec<Protocal>)->Option<(EtherType,Vec<u8>)>{
    let header = EthernetHeader::from(&packet);
    protocals.push(Protocal { 
        name: "Ethernet".to_string(),
        header: header.parsr2vec(), 
        payload: None });
    match ethertype {
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(packet.payload()){
                let header = ArpHeader::from(arp);
                protocals.push(Protocal { 
                    name: "ARP".to_string(),
                    header: header.parsr2vec(), 
                    payload: None });
            }else {
                protocals.push(
                    Protocal { 
                        name: "ARP".to_string(),
                        header: vec!["数据包过小，无法解析为ARP帧！".to_string()],
                        payload:None }
                );
            }
            None
        },
        EtherTypes::Vlan => {
            if let Some(vlan) = VlanPacket::new(packet.packet()){
                let header = VlanHeader::from(&vlan);
                protocals.push(Protocal { 
                    name: "Vlan".to_string(),
                    header: header.parsr2vec(), 
                    payload: None });
                if let Some(ether) = EthernetPacket::new(vlan.payload()){
                    handle_ethertype(vlan.get_ethertype(), ether, protocals)
                }else{
                    protocals.push(Protocal { 
                        name: "Ethernet".to_string(),
                        header: vec!["数据包过小，无法解析为以太网帧！".to_string()],
                        payload:Some(vlan.payload().to_vec()) }
                    );
                    None
                }
            }else {
                protocals.push(
                    Protocal { 
                        name: "Vlan".to_string(),
                        header: vec!["数据包过小，无法解析为Vlan帧！".to_string()],
                        payload:Some(packet.packet().to_vec()) }
                );
                None
            }
        },
        et =>{
            Some((et,packet.payload().to_vec()))
        }
    }
}
fn info_ethertype(ethertype:EtherType,packet: EthernetPacket,info:&mut PacketInfo)->Option<(EtherType,Vec<u8>)>{
    match ethertype {
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(packet.payload()){
                let header = ArpHeader::from(arp);
                info.by(header);
                None
            }else {
                None
            }
        },
        EtherTypes::Vlan => {
            if let Some(vlan) = VlanPacket::new(packet.packet()){
                let header = VlanHeader::from(&vlan);
                info.change(info.source.clone(), info.destination.clone(), info.finalprotocal.clone(), header.get_info());
                if let Some(ether) = EthernetPacket::new(vlan.payload()){
                    info_ethertype(vlan.get_ethertype(), ether,info)
                }else{
                    None
                }
            }else {
                None
            }
        },
        et =>{
            //可以继续往下解析
            Some((et,packet.payload().to_vec()))
        }
    }
}
pub struct EthernetHeader{
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
}
impl EthernetHeader {
    pub(crate) fn from(packet:&EthernetPacket)->Self{
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
        Self { 
            destination_mac: dest_mac.to_string(), 
            source_mac: src_mac.to_string(), 
            ether_type: packet.get_ethertype().to_string(), 
            packet_size:packet.packet().len() as u16,
            destination_mac_message:dest_message, 
            source_mac_message: src_message,
        } 
    }

    pub(crate) fn parsr2vec(self)->Vec<String>{
        vec![
            format!("源MAC地址:{}",self.source_mac),
            format!("目的MAC地址:{}",self.destination_mac),
            format!("以太类型:{}",self.ether_type),
            format!("包大小:{}",self.packet_size),
            format!("源MAC地址信息:{}",self.source_mac_message),
            format!("目的MAC地址信息:{}",self.destination_mac_message),
        ]
    }
}
impl HeaderFunc for EthernetHeader {
    fn get_info(&self)->String{
        format!("{} -> {} {}",self.source_mac,self.destination_mac,self.ether_type)
    }
    fn get_source(&self)->String{
        self.source_mac.clone()
    }
    fn get_destination(&self)->String{
        self.destination_mac.clone()
    }
    fn get_finalprotocal(&self) -> String {
        "Ethernet".to_string()
    }
}
pub struct VlanHeader{
    // 表示是否可以被丢弃
    drop_eligible_indicator:u8,
    // 表示设备类型
    ethertype:String,
    // 表示优先级码点
    priority_code_point:u8,
    // 表示虚拟局域网络标识符
    vlan_identifier:u16,
}
// 定义一个ArpMessage结构体,用于存储ARP消息
pub struct ArpHeader{
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
}
impl VlanHeader {
    fn from(packet:&VlanPacket)->Self{
        Self{
            drop_eligible_indicator:packet.get_drop_eligible_indicator(),
            ethertype:packet.get_ethertype().to_string(),
            priority_code_point:packet.get_priority_code_point().0,
            vlan_identifier:packet.get_vlan_identifier(),
        }
    }
    pub(crate) fn get_info(&self)->String{
        format!("{} {} {} {}",self.drop_eligible_indicator,self.ethertype,self.priority_code_point,self.vlan_identifier)
    }
    pub(crate) fn parsr2vec(self)->Vec<String>{
        vec![
            format!("是否可以被丢弃:{}",self.drop_eligible_indicator),
            format!("设备类型:{}",self.ethertype),
            format!("优先级码点:{}",self.priority_code_point),
            format!("虚拟局域网络标识符:{}",self.vlan_identifier),
        ]
    }
}
impl ArpHeader {
    fn from(packet:ArpPacket)->Self{
        Self { 
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
        }
    }
    pub(crate) fn parsr2vec(self)->Vec<String>{
        vec![
            format!("硬件类型:{}",self.hardware_type),
            format!("硬件地址长度:{}",self.hradware_address_length),
            format!("操作:{}",self.opretion),
            format!("协议地址长度:{}",self.protocal_address_length),
            format!("协议类型:{}",self.protocal_type),
            format!("发送者硬件地址:{}",self.sender_hardware_addr),
            format!("发送者协议地址:{}",self.sender_protocal_address),
            format!("目标硬件地址:{}",self.target_hardware_addr),
            format!("目标协议地址:{}",self.target_protocal_address),
        ]
    }
}
impl HeaderFunc for ArpHeader {
    fn get_info(&self)->String{
        format!("{} {} for {}",self.sender_protocal_address,self.opretion,self.target_protocal_address)
    }
    fn get_source(&self)->String{
        self.sender_protocal_address.clone()
    }
    fn get_destination(&self)->String{
        self.target_protocal_address.clone()
    }
    fn get_finalprotocal(&self) -> String {
        "ARP".to_string()
    }
}