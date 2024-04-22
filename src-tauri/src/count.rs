use std::{collections::HashMap, sync::{Arc, Mutex}};
use lazy_static::lazy_static;
use serde::Serialize;

use crate::info::HeaderInfo;

lazy_static!{
    pub static ref GLOBAL_COUNT_MESSAGE:Arc<Mutex<PacketCount>> = Arc::new(Mutex::new(PacketCount::new()));
}
#[derive(Serialize,Clone)]
pub struct PacketCount{
    pub(crate) total:u32,
    pub(crate) protocal_and_number_count:HashMap<String,u32>,
    pub(crate) ip_source_count:HashMap<String,u32>,
    pub(crate) ip_destination_count:HashMap<String,u32>,
    pub(crate) mac_source_count:HashMap<String,u32>,
    pub(crate) mac_destination_count:HashMap<String,u32>,
    pub(crate) port_source_count:HashMap<String,u32>,
    pub(crate) port_destination_count:HashMap<String,u32>,
    pub(crate) flow_count_by_second:Vec<u32>,//索引值就是时间顺序,统计每秒的流量
    pub(crate) size_count:Vec<u32>,//索引值就是大小 *10 ,超过1000kB的都算在1000kB
}
impl PacketCount {
    pub fn new()->Self{
        PacketCount{
            total:0,
            protocal_and_number_count:HashMap::new(),
            ip_source_count:HashMap::new(),
            ip_destination_count:HashMap::new(),
            mac_source_count:HashMap::new(),
            mac_destination_count:HashMap::new(),
            port_source_count:HashMap::new(),
            port_destination_count:HashMap::new(),
            flow_count_by_second:Vec::new(),
            size_count:vec![0;16]
        }
    }
    pub fn clear(&mut self){
        self.total = 0;
        self.protocal_and_number_count.clear();
        self.ip_source_count.clear();
        self.ip_destination_count.clear();
        self.mac_source_count.clear();
        self.mac_destination_count.clear();
        self.port_source_count.clear();
        self.port_destination_count.clear();
        self.flow_count_by_second.clear();
        self.size_count = vec![0;16];
    }
    pub fn push_flow(&mut self,flow:u32){
        self.flow_count_by_second.push(flow);
    }
    pub(crate) fn update_from_linkinfo(&mut self,linkinfo:&HeaderInfo){
        *self.protocal_and_number_count.entry(linkinfo.protocal.clone()).or_insert(0) += 1;
        *self.mac_source_count.entry(linkinfo.source.clone()).or_insert(0) += 1;
        *self.mac_destination_count.entry(linkinfo.destination.clone()).or_insert(0) += 1;
    }
    pub(crate) fn update_from_netinfo(&mut self,netinfo:&HeaderInfo){
        *self.protocal_and_number_count.entry(netinfo.protocal.clone()).or_insert(0) += 1;
        *self.ip_source_count.entry(netinfo.source.clone()).or_insert(0) += 1;
        *self.ip_destination_count.entry(netinfo.destination.clone()).or_insert(0) += 1;
    }
    pub(crate) fn update_from_transinfo(&mut self,transinfo:&HeaderInfo){
        *self.protocal_and_number_count.entry(transinfo.protocal.clone()).or_insert(0) += 1;
        *self.port_source_count.entry(transinfo.source.clone()).or_insert(0) += 1;
        *self.port_destination_count.entry(transinfo.destination.clone()).or_insert(0) += 1;
    }
}
impl Default for PacketCount {
    fn default()->Self{
        PacketCount::new()
    }
}
