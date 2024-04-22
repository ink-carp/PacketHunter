//基础工具库

use pcap::{ConnectionStatus, Device};
use std::time::{SystemTime, Duration};
use chrono::{DateTime, Local};

///用于指示header应该拥有的行为
pub(crate) trait HeaderFunc {
    fn get_source(&self) -> String;
    fn get_destination(&self) -> String;
    fn get_info(&self) -> String;
}
pub struct DeviceGoodChecker;
impl DeviceGoodChecker {
    // 定义一个检查设备是否符合条件的闭包
    pub fn good(dev: &Device) -> bool {
        (!dev.addresses.is_empty() && dev.flags.is_up() && dev.flags.is_running() && dev.flags.connection_status == ConnectionStatus::Connected) ||
        (dev.flags.is_loopback()&&dev.flags.is_running())
    }
}
//--------------------------------------------------
//用于发送的类型
#[derive(Clone, serde::Serialize)]
pub struct Stream{
  pub name:String,
  pub receive:u32,
  pub drop:u32,
}
#[derive(Clone, serde::Serialize)]
pub struct SimpleDevice{
    connected:bool,
    wireless:bool,
    name:String,
    description:String,
    ipv4:Option<String>,//string | null
    ipv6:Option<String>,
}
#[derive(Clone, serde::Serialize)]
pub struct Protocal{
    pub(crate) name:String,
    pub(crate) header:Vec<String>,
    pub(crate) payload:Option<Vec<u8>>
}




impl SimpleDevice {
    pub fn from(dev:&Device)->SimpleDevice{
        let ipv4 = dev.addresses.iter().find_map(|addr| {
            if addr.addr.is_ipv4() {
                Some(addr.addr.to_string())
            } else {
                None
            }
        });
        let ipv6 = dev.addresses.iter().find_map(|addr| {
            if addr.addr.is_ipv6() {
                Some(addr.addr.to_string())
            } else {
                None
            }
        });
        SimpleDevice{
            connected:DeviceGoodChecker::good(dev),
            wireless:dev.flags.is_wireless(),
            name:dev.name.clone(),
            description:dev.desc.clone().unwrap_or("Unknown Device".to_string()),
            ipv4,
            ipv6
        }
    }
    pub fn get_connected(&self)->bool{
        self.connected
    }
}
//为数据包实现解析


impl Protocal {
    pub fn get_name(&self)->String{
        self.name.clone()
    }
    pub fn get_header(&self)->Vec<String>{
        self.header.clone()
    }
    pub fn get_payload(&self)->Option<Vec<u8>>{
        self.payload.clone()
    }
}
























//===========================>
//工具函数
pub(crate) fn timeval_to_china_time(tv_sec:i32,tv_usec:i32) -> String {
    // 计算时间戳，tv_sec 秒数 + tv_usec 微秒数
    let timestamp = tv_sec as u64 * 1_000 + tv_usec as u64 / 1_000;

    // 将时间戳转换为 SystemTime
    let system_time = SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp);

    // 将 SystemTime 转换为本地时间
    
    DateTime::<Local>::from(system_time).to_string()
}