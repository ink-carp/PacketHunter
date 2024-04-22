export interface TransportLayer {
    Tcp?:TcpMessage,
    Udp?:UdpMessage,
    Icmp?:IcmpMessage,
    Icmpv6?:Icmpv6Message,
}
export interface TcpMessage{
    acknownledgement:number, // 确认号
    sequence:number, // 序列号
    window:number, // 窗口大小
    flags:number, // 标志位
    payload:Uint8Array, // 数据
    checksum:number, // 校验和
    data_offset:number, // 数据偏移
    reserved:number, // 保留位
    source_port:number, // 源端口
    urgent_pointer:number, // 紧急指针
    destination_port:number, // 目的端口
    //暂时不对option进行解释，由前端进行解释
    options:Uint8Array, // 选项
}
export interface  UdpMessage{
    source_port:number, // 源端口
    destination_port:number, // 目的端口
    length:number, // 长度
    checksum:number, // 校验和
    payload:Uint8Array, // 数据
}
export interface IcmpMessage{
    icmp_type:number, // ICMP类型
    icmp_code:number, // ICMP代码
    checksum:number, // 校验和
    data:Uint8Array, // 数据
}
export interface Icmpv6Message{
    icmpv6_type:number, // ICMPv6类型
    icmpv6_code:number, // ICMPv6代码
    checksum:number, // 校验和
    data:Uint8Array, // 数据
}
export function trans_parser(trans:TransportLayer):string[]{
    let ret:string[] = [];
    if(trans.Tcp){
        ret.push("源端口:"+trans.Tcp.source_port);
        ret.push("确认号:" + trans.Tcp.acknownledgement);
        ret.push("序列号:" + trans.Tcp.sequence);
        ret.push("窗口大小:" + trans.Tcp.window);
        ret.push("标志位:" + trans.Tcp.flags);
        ret.push("校验和:" + trans.Tcp.checksum);
        ret.push("数据偏移:" + trans.Tcp.data_offset);
        ret.push("保留位:" + trans.Tcp.reserved);
        ret.push("紧急指针:" + trans.Tcp.urgent_pointer);
        ret.push("目的端口:" + trans.Tcp.destination_port);
        ret.push("选项:" + trans.Tcp.options);
    }
    else if(trans.Udp){
        ret.push("源端口:" + trans.Udp.source_port);
        ret.push("目的端口:" + trans.Udp.destination_port);
        ret.push("长度:" + trans.Udp.length);
        ret.push("校验和:" + trans.Udp.checksum);
    }
    else if(trans.Icmp){
        ret.push("ICMP类型:" + trans.Icmp.icmp_type);
        ret.push("ICMP代码:" + trans.Icmp.icmp_code);
        ret.push("校验和:" + trans.Icmp.checksum);
    }
    else if(trans.Icmpv6){
        ret.push("ICMPv6类型:" + trans.Icmpv6.icmpv6_type);
        ret.push("ICMPv6代码:" + trans.Icmpv6.icmpv6_code);
        ret.push("校验和:" + trans.Icmpv6.checksum);
    }
    return ret;
}
export function trans_payload(trans:TransportLayer):Uint8Array{
    if(trans.Tcp){
        return trans.Tcp.payload;
    }else if(trans.Udp){
        return trans.Udp.payload;
    }else if(trans.Icmp){
        return trans.Icmp.data;
    }else if(trans.Icmpv6){
        return trans.Icmpv6.data;
    }
    return new Uint8Array();
}