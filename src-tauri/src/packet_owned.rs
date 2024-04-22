use pcap::{Linktype, PacketCodec, PacketHeader};
use pnet::packet::ethernet::EtherTypes;
use crate::linklayer::{info_linklayer,parse_linklayer};
use crate::networklayer::{info_netlayer,parse_netlayer};
use crate::transformlayer::{info_translayer,parse_translayer};
use crate::info::{PacketInfo,HeaderInfo};
use crate::count::GLOBAL_COUNT_MESSAGE;
use crate::tools::{timeval_to_china_time, Protocal};


pub struct Codec;
impl PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        PacketOwned {
            header: *packet.header,
            data: packet.data.into(),
        }
    }
}
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>,
}
impl PacketOwned {
    ///parse应该要能返回一个protocal栈
    ///将原始数据一层一层的解析
    pub fn parse(&self,linktype:&Linktype,index:u32)->Vec<Protocal>{
        let mut ret = Vec::<Protocal>::new();
        ret.push(Protocal{
            name:format!("Frame {index}"),
            header:vec![
                format!("Frame:{index}"),
                format!("{} bytes on wire ({} bits)",self.header.len,self.header.len*8),
                format!("{} bytes captured ({} bits)",self.header.caplen,self.header.caplen*8),
                format!("Encapsulation type: {}",linktype.get_name().unwrap_or("Unknown".to_string())),
                format!("Arrival Time: {}",timeval_to_china_time(self.header.ts.tv_sec, self.header.ts.tv_usec)),
                ],
            payload:None
        });
        if let Some((et,payload)) = parse_linklayer(&self.data,linktype,&mut ret){
            let trans;
            if *linktype == Linktype::NULL{
                trans = parse_netlayer(payload[0], payload[4..].to_vec(),&mut ret);
            }else if et == EtherTypes::Ipv4 {
                trans = parse_netlayer(2, payload,&mut ret);
            }
            else if et == EtherTypes::Ipv6{
                trans = parse_netlayer(24, payload,&mut ret);
            }else {
                ret.push(Protocal{
                    name:format!("{}",et),
                    header:vec![format!("协议 {} 暂不支持解析！",et)],
                    payload:Some(payload)
                });
                trans = None;
            }
            if let Some((next,payload)) = trans {
                parse_translayer(next, payload, &mut ret);
            }
        }
        ret
    }
    ///获取数据包的信息,同时进行统计
    pub fn get_info(&self,linktype:&Linktype,index:u32)->PacketInfo{
        //包信息初始化
        let mut link_info = HeaderInfo::default();
        let mut net_info = HeaderInfo::default();
        let mut trans_info = HeaderInfo::default();


        let mut net = None;
        if let Some((et,payload)) = info_linklayer(&self.data,linktype,&mut link_info){
            if *linktype == Linktype::NULL{
                net = info_netlayer(payload[0], payload[4..].to_vec(),&mut net_info);
            }else if et == EtherTypes::Ipv4 {
                net = info_netlayer(2, payload,&mut net_info);
            }
            else if et == EtherTypes::Ipv6{
                net = info_netlayer(24, payload,&mut net_info);
            }else {
                //不关心其他协议
                net_info.protocal = format!("{}",et);
                net = None;
            }
        }
        if let Some((next,payload)) = net {
            info_translayer(next, payload,&mut trans_info);
        }
        {
            //统计块
            let global_count = GLOBAL_COUNT_MESSAGE.clone();
            global_count.lock().unwrap().total += 1;//总包数加1
            if self.header.caplen < 1500{
                global_count.lock().unwrap().size_count[self.header.caplen as usize/100] += 1;
            }else {
                global_count.lock().unwrap().size_count[15] += 1;
            }
            global_count.lock().unwrap().update_from_linkinfo(&link_info);
            global_count.lock().unwrap().update_from_netinfo(&net_info);
            global_count.lock().unwrap().update_from_transinfo(&trans_info);
        }
        PacketInfo::from(self.header, index, link_info, net_info, trans_info)
    }
}