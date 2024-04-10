// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//外部库
use pcap::{Active, Capture, Dead, Device, Inactive, Linktype, Packet, PacketCodec};
use tauri::{Window,State};
use app::*;

use std::cmp::Ordering;
//标准库
use std::{fs, thread};
use std::time::Duration;
use std::sync::{Arc, Mutex};

static FILE_LIST_PATH:&'static str = "./file_list.txt";
struct FlowRunState{is_running:Arc<Mutex<bool>>}
struct CapRunState{is_running:Arc<Mutex<bool>>}
struct FlowThreadState{handle:Arc<Mutex<Option<thread::JoinHandle<()>>>>}
struct CapThreadState{handle:Arc<Mutex<Option<thread::JoinHandle<()>>>>}
struct DeadCap {cap:Option<Capture<Dead>>}
#[derive(Default)]
struct OfflineBank{
  linktype:Mutex<i32>,
  device_name:Mutex<Option<String>>,
  device_description:Mutex<Option<String>>,
  data:Mutex<Vec<PacketDetail>>
}
#[derive(Default)]
struct ActiveBank{
  linktype:Mutex<i32>,
  device_name:Mutex<Option<String>>,
  device_description:Mutex<Option<String>>,
  data:Arc<Mutex<Vec<PacketDetail>>>,
  packet:Arc<Mutex<Vec<PacketOwned>>>,
}
fn main() {
  tauri::Builder::default()
  .manage(FlowRunState{is_running:Default::default()})
  .manage(FlowThreadState{handle:Default::default()})
  .manage(CapRunState{is_running:Default::default()})
  .manage(CapThreadState{handle:Default::default()})
  .manage(OfflineBank::default())
  .manage(ActiveBank::default())
  .invoke_handler(tauri::generate_handler![
    get_device,//获取设备列表
    flow_start_send,//启动流量监控
    flow_stop_send,//停止流量监控
    //以上函数应该在前端的Adapter页面被调用
    bpf_analyzer,//Bpf语法分析
    //以上函数应该在前端的Bpf页面被调用
    open_pcap_file,
    clear_offline_bank,
    get_offline_linklayer,
    get_offline_netlayer,
    get_offline_translayer,
    //以上函数应该在前端的Offline页面被调用
    start_capture,
    stop_capture,
    save_to_file,
    clear_active_bank,
    get_active_linklayer,
    get_active_netlayer,
    get_active_translayer,
    //以上函数应该在前端的Active页面被调用
    get_file_list,
    //以上函数应该在前端的ChooseFile页面被调用
  ])
  .run(tauri::generate_context!())
  .expect("error while running tauri application");
}
//自定义函数
#[tauri::command]
fn get_device()->Result<Vec<SimpleDevice>,String>{
  match Device::list() {
      Ok(devices) => {
        let mut ret = Vec::<SimpleDevice>::with_capacity(devices.len());
        for dev in devices{
          ret.push(SimpleDevice::from(dev));
        }
        ret.sort_by(|_b,a| if a.get_connected() {Ordering::Greater}else{Ordering::Less});
        Ok(ret)
      },
      Err(e) => {
        Err(e.to_string())
      }
  }
}
//对适配器流量的捕捉函数,应该于前端的Adaoter页面加载和主动获取适配器列表时被调用
//内部应该启动一个线程，不断的先前端发送流量信息
//配套的应该有一个停止函数
#[tauri::command]
fn flow_start_send(window:Window,flow_run:State<FlowRunState>,flow_handle:State<FlowThreadState>){
  if let Some(handle) = flow_handle.handle.lock().unwrap().take(){
    println!("Start send asgin!");
    *flow_run.is_running.lock().unwrap() = false;
    handle.join().expect("Failed to join previous task!");
  }
  
  let device:Vec<Device> = Device::list().unwrap().into_iter().filter(|d| DeviceGoodChecker.good(d)).collect();
  let caps:Vec<(String,Result<Capture<Inactive>,_>)> = device.into_iter()
  .map(|d| (d.name.clone(),Capture::from_device(d))).collect();
  if caps.iter().all(|item| item.1.is_err()){
    return;
  }
  let caps = caps.into_iter().map(|(name,cap)| (name,cap.unwrap().buffer_size(1024*1024).snaplen(1024*100).open())).collect::<Vec<(String,Result<Capture<Active>,_>)>>();
  //仅在条件允许的情况下才启动线程                                    
  if caps.iter().all(|item| item.1.is_ok()){
    let mut caps = caps
    .into_iter()
    .map(|(name,cap)| (name,cap.unwrap()))
    .collect::<Vec<(String,Capture<Active>)>>();

    *flow_run.is_running.lock().unwrap() = true;
    //送入线程内部，每次循环都判断状态
    let run_state = flow_run.is_running.clone();
    let newhandle = thread::spawn(move || {
      loop {
        if !*run_state.lock().unwrap(){
          break;
        }
        let mut flow = Flow{ nets:Vec::<Stream>::with_capacity(caps.len())};
        for (name,cap) in caps.iter_mut() {
        let stat = cap.stats().unwrap();
          let new_stream = Stream{name:name.clone(),receive:stat.received,drop:stat.if_dropped};
          flow.nets.push(new_stream);
        }
        let _ = window.emit("Flow", flow);
        //println!("Send a Flow!");
        std::thread::sleep(Duration::from_secs(1));
      }
    });
    flow_handle.handle.lock().unwrap().replace(newhandle);
  }
  println!("Flow Start send!");
}
//停止流量发送
//不应该主动停止，应该在前端onDestroy触发时调用，以销毁线程
#[tauri::command]
fn flow_stop_send(flow_run:State<FlowRunState>,flow_handle:State<FlowThreadState>){
  if let Some(handle) = flow_handle.handle.lock().unwrap().take(){
    println!("Flow Stop send!");
    *flow_run.is_running.lock().unwrap() = false;
    handle.join().expect("Failed to join previous task!");
  }
}
//对Bpf程序的语法分析函数
#[tauri::command]
fn bpf_analyzer(code:&str)->Result<(),&str>{
  let dead_cap = Capture::dead(Linktype::from_name("loop").unwrap()).unwrap();
  if dead_cap.compile(code, false).is_ok(){
    Ok(())
  }else {
      Err("Invalid!")
  }
}
//对pcap文件的打开函数，成功的话应该返回Info信息
#[tauri::command]
fn open_pcap_file(path:&str,bpf:&str,offline_bank:State<OfflineBank>)->Result<Vec<PacketInfo>,String>{
  let path = path.trim();
  println!("Start open file:{path}!");
  let mut ret:Vec::<PacketInfo> = Vec::<PacketInfo>::with_capacity(1024);//默认分配1024
  match Capture::from_file(path){
    Ok(mut cap) =>{
      match cap.filter(bpf, true){
          Ok(_) => {
            let linktype = cap.get_datalink();
            for (index,packet) in cap.iter(Codec).flatten().enumerate(){
              let new_coin = PacketDetail::from(packet,index,linktype);
              ret.push(new_coin.get_info());
              offline_bank.data.lock().unwrap().push(new_coin);
            }
          },
          Err(e) =>{
            println!("Filter Failed!");
            return Err(e.to_string());
          },
      }
    },
    Err(e) =>{
      println!("Open Failed!");
      return Err(e.to_string());
    },
  }
  println!("Open Successd!");
  if let Ok(files) = fs::read_to_string(FILE_LIST_PATH){
    let mut files:Vec<String> = files.split("\n").map(|s| s.trim().to_string()).collect();
    if let None = files.iter().find(|x| **x == path.to_string()){
      files.push(path.to_string());
      fs::write(FILE_LIST_PATH, files.join("\n").as_bytes()).unwrap();
    }
  }
  Ok(ret)
}
//在前端离开Offline页面时被调用，即onDestroy时
//清除离线的数据包
#[tauri::command]
fn clear_offline_bank(offline_bank:State<OfflineBank>){
  let mut data = offline_bank.data.lock().unwrap();
  data.clear();
  data.shrink_to_fit();
  *offline_bank.device_description.lock().unwrap() = None;
  *offline_bank.device_name.lock().unwrap() = None;
  *offline_bank.linktype.lock().unwrap() = i32::default();
}
//在前端选中活跃的设备时被调用
//使用被选中的设备和Bpf创建一个活跃的Capture
//并在线程中不断的捕获数据包发往前端
#[tauri::command]
fn start_capture(bpf:String,devname:String,window:Window,active_bank:State<ActiveBank>,cap_run:State<CapRunState>,cap_handle:State<CapThreadState>)->Result<(),String>{
  if let Some(dev) = Device::list().unwrap().into_iter().find(|d| d.name == devname){
    if let Ok(cap) = Capture::from_device(dev)
    .map_err(|e| e.to_string() )?
    .immediate_mode(true)
    //缓冲区没必要太大，因为数据会存储在bank中
    .buffer_size(1024*1024)
    //捕获的最大数据包不超过100KB
    .snaplen(1024*100)
    .open()
    {
      let mut cap = cap.setnonblock().map_err(|e|e.to_string())?;
      let datalink = cap.get_datalink();
      let mut codec = Codec;
      cap.filter(&bpf, true).map_err(|e|e.to_string())?;
      let data = active_bank.data.clone();
      let pac = active_bank.packet.clone();
      //应该在线程开始执行前将状态设置为true
      *cap_run.is_running.lock().unwrap() = true;
      let run_state = cap_run.is_running.clone();
      let newhandle = thread::spawn(move ||{
        let mut index = 0;
        loop {
          if *run_state.lock().unwrap() == false{
            break;
          }
          if let Ok(packet) = cap.next_packet(){
            let new_coin = PacketDetail::from(codec.decode(packet.clone()),index,datalink);
            let _ = window.emit("active", new_coin.get_info());
            println!("Send a Active Info!");
            data.lock().unwrap().push(new_coin);
            pac.lock().unwrap().push(codec.decode(packet));
            index+=1;
          }
        }
      });
      cap_handle.handle.lock().unwrap().replace(newhandle);
    }
  }
  println!("Start capture!");
  Ok(())
}
#[tauri::command]
fn stop_capture(cap_run:State<CapRunState>,cap_handle:State<CapThreadState>){
  if let Some(handle) = cap_handle.handle.lock().unwrap().take(){
    println!("Stop send!");
    *cap_run.is_running.lock().unwrap() = false;
    handle.join().expect("Failed to join previous task!");
  }
}
//只能在前端的Active页面被调用
//将活跃的Capture所捕获的数据包保存为文件
//并在file_list中添加该文件
#[tauri::command]
fn save_to_file(path:&str,active_bank:State<ActiveBank>)->Result<(),String>{
  let packet = active_bank.packet.lock().unwrap();
  let cap = Capture::dead(Linktype(1)).map_err(|e| e.to_string())?;
  let mut save = cap.savefile(path).map_err(|e|e.to_string())?;
  for p in packet.iter(){
    save.write(&Packet{header:&p.header,data:&p.data});
  }
  save.flush().map_err(|e|e.to_string())?;
  if let Ok(files) = fs::read_to_string(FILE_LIST_PATH){
    let mut files:Vec<String> = files.split("\n").map(|s| s.trim().to_string()).collect();
    if let None = files.iter().find(|x| **x == path.to_string()){
      files.push(path.to_string());
      fs::write(FILE_LIST_PATH, files.join("\n").as_bytes()).unwrap();
    }
  }
  Ok(())
}
#[tauri::command]
fn clear_active_bank(active_bank:State<ActiveBank>){
  let mut data = active_bank.data.lock().unwrap();
  data.clear();
  data.shrink_to_fit();
  let mut packet = active_bank.packet.lock().unwrap();
  packet.clear();
  packet.shrink_to_fit();
  *active_bank.device_description.lock().unwrap() = None;
  *active_bank.device_name.lock().unwrap() = None;
  *active_bank.linktype.lock().unwrap() = i32::default();
}
#[tauri::command]
fn get_file_list()->Result<Vec<String>,()>{
  use std::fs;
  use std::path::Path;
  let mut new_file_list = Vec::<String>::new();
  let temp = fs::read_to_string(FILE_LIST_PATH).map_err(|_| {let _ = fs::File::create(FILE_LIST_PATH);})?;
  let lines:Vec<String> = temp.split("\n").map(|s| s.trim().to_string()).collect();
  for line in lines {
    let file_path = Path::new(&line);
    //file_path 的 end_with不可用
    // 检查文件是否存在
    if file_path.exists() && line.ends_with(".pcap"){
        new_file_list.push(line);
    }
  }
  //fs::write(FILE_LIST_PATH, new_file_list.join("\n")).unwrap();
  Ok(new_file_list)
}

#[tauri::command]
fn get_offline_linklayer(index:usize,offline_bank:State<OfflineBank>)->Result<LinkLayer,UndecodeProtocal>{
  //保证该函数被调用时，index不超过bank长度且bank不为空
  offline_bank.data.lock().unwrap().get(index).unwrap().get_linklayer()
}
#[tauri::command]
fn get_offline_netlayer(index:usize,offline_bank:State<OfflineBank>)->Option<Result<NetworkLayer,UndecodeProtocal>>{
  //保证该函数被调用时，index不超过bank长度且bank不为空
  offline_bank.data.lock().unwrap().get(index).unwrap().get_net_layer()
}
#[tauri::command]
fn get_offline_translayer(index:usize,offline_bank:State<OfflineBank>)->Option<Result<TransformLayer,UndecodeProtocal>>{
  //保证该函数被调用时，index不超过bank长度且bank不为空
  offline_bank.data.lock().unwrap().get(index).unwrap().get_trans_layer()
}
#[tauri::command]
fn get_active_linklayer(index:usize,active_bank:State<ActiveBank>)->Result<LinkLayer,UndecodeProtocal>{
  //保证该函数被调用时，index不超过bank长度且bank不为空
  active_bank.data.lock().unwrap().get(index).unwrap().get_linklayer()
}
#[tauri::command]
fn get_active_netlayer(index:usize,active_bank:State<ActiveBank>)->Option<Result<NetworkLayer,UndecodeProtocal>>{
  //保证该函数被调用时，index不超过bank长度且bank不为空
  active_bank.data.lock().unwrap().get(index).unwrap().get_net_layer()
}
#[tauri::command]
fn get_active_translayer(index:usize,active_bank:State<ActiveBank>)->Option<Result<TransformLayer,UndecodeProtocal>>{
  //保证该函数被调用时，index不超过bank长度且bank不为空
  active_bank.data.lock().unwrap().get(index).unwrap().get_trans_layer()
}