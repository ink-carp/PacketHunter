// 定义 LinkLayer 类型
export interface LinkLayer {
    Ethernet?: Ethernet;
    Vlan?: Vlan;
    Arp?: Arp;
    Null?: Uint8Array; // 使用 Uint8Array 表示 Box<[u8]>
}
export interface Ethernet{
    destination_mac:String,
    source_mac:String,
    ether_type:String,
    packet_size:number,
    destination_mac_message:String,
    source_mac_message:String,
    payload:Uint8Array,
}
export interface Vlan{
    drop_eligible_indicator:number,
    ethertype:String,
    priority_code_point:number,
    vlan_identifier:number,
    payload:Ethernet | null,
}
export interface Arp{
     protocal_address_length:number,
     hardware_type:String,
     opretion:String,
     protocal_type:String,
     sender_hardware_addr:String,
     sender_protocal_address:String,
     target_hardware_addr:String,
     target_protocal_address:String,
     target_mac_type:String
}
export function link_parser(link:LinkLayer):string[]{
    let ret:string[] = [];
    if(link.Ethernet){
        ret.push("以太网类型:" + link.Ethernet.ether_type);
        ret.push("数据包大小:" + link.Ethernet.packet_size);
        ret.push("源MAC地址:" + link.Ethernet.source_mac);
        ret.push("源MAC地址消息:" + link.Ethernet.source_mac_message);
        ret.push("目的MAC地址:" + link.Ethernet.destination_mac);
        ret.push("目的MAC地址消息:" + link.Ethernet.destination_mac_message);
    }
    else if(link.Vlan){
        ret.push("丢弃标志位:" + link.Vlan.drop_eligible_indicator);
        ret.push("以太网类型:" + link.Vlan.ethertype);
        ret.push("优先级代码点:" + link.Vlan.priority_code_point);
        ret.push("VLAN标识符:" + link.Vlan.vlan_identifier);
        if (link.Vlan.payload) {
            ret.push("负载:");
            ret.push("  目的MAC地址:" + link.Vlan.payload.destination_mac);
            ret.push("  源MAC地址:" + link.Vlan.payload.source_mac);
            ret.push("  以太网类型:" + link.Vlan.payload.ether_type);
            ret.push("  数据包大小:" + link.Vlan.payload.packet_size);
            ret.push("  目的MAC地址消息:" + link.Vlan.payload.destination_mac_message);
            ret.push("  源MAC地址消息:" + link.Vlan.payload.source_mac_message);
        }
    }
    else if(link.Arp){
        ret.push("协议类型:" + link.Arp.protocal_type);
        ret.push("硬件类型:" + link.Arp.hardware_type);
        ret.push("发送方硬件地址:" + link.Arp.sender_hardware_addr);
        ret.push("发送方协议地址:" + link.Arp.sender_protocal_address);
        ret.push("目标硬件地址:" + link.Arp.target_hardware_addr);
        ret.push("目标协议地址:" + link.Arp.target_protocal_address);
        ret.push("协议地址长度:" + link.Arp.protocal_address_length);
        ret.push("操作:" + link.Arp.opretion);
    }
    return ret;
}
export function link_payload(link:LinkLayer):Uint8Array{
    if(link.Ethernet){
        return link.Ethernet.payload;
    }
    else if(link.Vlan){
        if(link.Vlan.payload){
            return link.Vlan.payload.payload;
        }else{
            return new Uint8Array();
        }
    }
    else if(link.Null){
        return link.Null;
    }else{
        return new Uint8Array();
    }
}