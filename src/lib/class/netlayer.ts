export interface NetworkLayer {
    Ipv4?: Ipv4Message,
    Ipv6?: Ipv6Message,
}
export interface Ipv4Message{
    ttl:number,
    // Time-to-live
    version:number,
    // 协议版本
    header_length:number,
    // 头部长度
    dscp:number,
    //  Differentiated Services Code Point
    ecn:number,
    // Explicit Congestion Notification
    flags:number,
    // 标志
    next_level_protocal:number,
    // 下一级协议
    checksum:number,
    // 校验和
    total_length:number,
    // 总长度
    fragment_offset:number,
    // 分段偏移
    identification:number,
    // 标识符
    source:String,
    // 源IP地址
    destination_ip:String,
    // 目的IP地址
    options:Uint8Array,//由前端进行解释
    // 可选参数
    payload:Uint8Array
    // 有效负载
}
export interface Ipv6Message{
    // 目的IP地址
    destination_ip:String,
    // 流标签
    flow_label:number,
    // 跳数
    hop_limit:number,
    // 负载长度
    payload_length:number,
    // 源IP地址
    source_ip:String,
    // 流量类
    traffic_class:number,
    // 版本
    version:number,
    // 下一级协议
    next_level_protocal:number,
    
    payload:Uint8Array
    // 有效负载
}
export function net_parser(net:NetworkLayer):string[]{
    let ret:string[] = [];
    if(net.Ipv4){
        ret.push("版本:" + net.Ipv4.version);
        ret.push("源IP地址:" + net.Ipv4.source);
        ret.push("目的IP地址:" + net.Ipv4.destination_ip);
        ret.push("总长度:" + net.Ipv4.total_length);
        ret.push("校验和:" + net.Ipv4.checksum);
        ret.push("分段偏移:" + net.Ipv4.fragment_offset);
        ret.push("标识符:" + net.Ipv4.identification);
        ret.push("TTL:" + net.Ipv4.ttl);
        ret.push("头部长度:" + net.Ipv4.header_length);
        ret.push("DSCP:" + net.Ipv4.dscp);
        ret.push("ECN:" + net.Ipv4.ecn);
        ret.push("标志:" + net.Ipv4.flags);
        ret.push("下一级协议:" + net.Ipv4.next_level_protocal);
        ret.push("可选参数:" + net.Ipv4.options);
    }else if(net.Ipv6){
        ret.push("版本:" + net.Ipv6.version);
        ret.push("源IP地址:" + net.Ipv6.source_ip);
        ret.push("目的IP地址:" + net.Ipv6.destination_ip);
        ret.push("负载长度:" + net.Ipv6.payload_length);
        ret.push("下一级协议:" + net.Ipv6.next_level_protocal);
        ret.push("流标签:" + net.Ipv6.flow_label);
        ret.push("跳数:" + net.Ipv6.hop_limit);
        ret.push("流量类:" + net.Ipv6.traffic_class);
    }
    return ret;
}
export function net_payload(net:NetworkLayer):Uint8Array{
    if(net.Ipv4){
        return net.Ipv4.payload;
    }else if(net.Ipv6){
        return net.Ipv6.payload;
    }
    return new Uint8Array();
}