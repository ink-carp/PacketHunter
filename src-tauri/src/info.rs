use pcap::PacketHeader;
use crate::tools::{timeval_to_china_time,HeaderFunc};

#[derive(Clone, serde::Serialize)]
pub(crate) struct HeaderInfo{
    pub(crate) source:String,
    pub(crate) destination:String,
    pub(crate) protocal:String,
    pub(crate) info:String,
}
impl HeaderInfo {
    pub(crate) fn by(&mut self,header:impl HeaderFunc){
        self.source = header.get_source();
        self.destination = header.get_destination();
        self.info = header.get_info();
    }
    // pub(crate) fn set_source(&mut self,source:String){
    //     self.source = source;
    // }
    // pub(crate) fn set_destination(&mut self,destination:String){
    //     self.destination = destination;
    // }
    pub(crate) fn set_protocal(&mut self,protocal:String){
        self.protocal = protocal;
    }
    pub(crate) fn set_info(&mut self,info:String){
        self.info = info;
    }
}
impl Default for HeaderInfo {
    fn default() -> Self {
        HeaderInfo {
            source: "Unkonwn".to_string(),
            destination: "Unknown".to_string(),
            protocal: "Unknown".to_string(),
            info: "".to_string(),
        }
    }
}












#[derive(Clone, serde::Serialize)]
pub struct PacketInfo{
    pub(crate) index:u32,
    pub(crate) len:u32,
    pub(crate) caplen:u32,
    pub(crate) time:String,
    pub(crate) linkinfo:HeaderInfo,
    pub(crate) netinfo:HeaderInfo,
    pub(crate) transinfo:HeaderInfo,
}

impl PacketInfo {
    pub(crate) fn from(ph:PacketHeader,index:u32,linkinfo:HeaderInfo,netinfo:HeaderInfo,transinfo:HeaderInfo)->Self{
        Self{
            index,
            len:ph.len,
            caplen:ph.caplen,
            time:timeval_to_china_time(ph.ts.tv_sec, ph.ts.tv_usec),
            linkinfo,
            netinfo,
            transinfo,
        }
    }
}