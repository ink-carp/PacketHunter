// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(non_snake_case)]
//外部库
use pcap::{Active, Capture, Device, Inactive, Linktype, Packet,PacketCodec};
use tauri::{State, Window};
use PacketHunter::*;

use std::io::Write;
//标准库
use std::{fs, thread};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::cmp::Ordering;
use std::path::Path;

static FILE_LIST_PATH:&str = "./file_list.txt";
struct RunState{is_running:Arc<Mutex<bool>>}
struct ThreadState{handle:Arc<Mutex<Option<thread::JoinHandle<()>>>>}
struct Bank{
  linktype:Mutex<Option<Linktype>>,
  packets:Arc<Mutex<Vec<PacketOwned>>>,
}
fn main() {
  tauri::Builder::default()
  //全局状态初始化并托管
  .manage(RunState{is_running:Arc::new(Mutex::new(false))})
  .manage(ThreadState{handle:Arc::new(Mutex::new(None))})
  .manage(Bank{linktype:Mutex::new(None),packets:Arc::new(Mutex::new(Vec::new()))})


  .invoke_handler(tauri::generate_handler![
    get_device,//获取设备列表
    bpf_analyzer,//Bpf语法分析
    open_pcap_file,

    //-------------------------------------
    start_capture,
    save_to_file,
    //以上函数应该在前端的Active页面被调用
    get_file_list,
    clear_bank,
    get_detail,
    stop_thread
  ])
  .run(tauri::generate_context!())
  .expect("error while running tauri application");
}
///获取简单的设备信息，用于前端显示
///启动一个线程用于监控设备信息
#[tauri::command]
fn get_device(window:Window,flow_run:State<RunState>,flow_handle:State<ThreadState>)->Result<Vec<SimpleDevice>,String>{
  match Device::list() {
      Ok(devices) => {
        let mut ret = Vec::<SimpleDevice>::with_capacity(devices.len());
        for dev in devices.iter(){
          ret.push(SimpleDevice::from(dev));
        }
        ret.sort_by(|_b,a| if a.get_connected() {Ordering::Greater}else{Ordering::Less});

        //启动监控线程
        //启动前先检查是否已经启动过了
        if let Some(handle) = flow_handle.handle.lock().unwrap().take(){
          dbg!("There is a previous task running!\nThen it will stop and restart!");
          *flow_run.is_running.lock().unwrap() = false;
          handle.join().expect("Failed to join previous task!");
          //结束上一个线程
        }
        //筛选出符合条件的设备
        let good_devices:Vec<Device> = devices.into_iter().filter(DeviceGoodChecker::good).collect();
        let caps:Vec<(String,Result<Capture<Inactive>,_>)> = good_devices.into_iter()
        .map(|d| (d.name.clone(),Capture::from_device(d))).collect();
        if caps.iter().any(|item| item.1.is_err()){
          return Err("Failed to open device!".to_string());
        }
        let caps = caps.into_iter().map(|(name,cap)| (name,cap.unwrap().buffer_size(1024*100).snaplen(1024*100).open())).collect::<Vec<(String,Result<Capture<Active>,_>)>>();
        if caps.iter().any(|item| item.1.is_err()){
          return Err("Failed to open device!".to_string());
        }
        let mut caps = caps
        .into_iter()
        .map(|(name,cap)| (name,cap.unwrap()))
        .collect::<Vec<(String,Capture<Active>)>>();
        //将状态设置为true
        *flow_run.is_running.lock().unwrap() = true;
        //送入线程内部，每次循环都判断状态
        let run_state = flow_run.is_running.clone();
        let newhandle = thread::spawn(move || {
          loop {
            if !*run_state.lock().unwrap(){
              break;
            }
            let mut payload = Vec::<Stream>::with_capacity(caps.len());
            for (name,cap) in caps.iter_mut() {
            let stat = cap.stats().unwrap();
              let new_stream = Stream{name:name.clone(),receive:stat.received,drop:stat.if_dropped};
              payload.push(new_stream);
            }
            let _ = window.emit("Flow", payload);
            //println!("Send a Flow!");
            std::thread::sleep(Duration::from_secs(1));
          }
        });
        flow_handle.handle.lock().unwrap().replace(newhandle);
        Ok(ret)
      },
      Err(e) => {
        Err(e.to_string())
      }
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
///对pcap文件的打开函数，成功的话应该返回Info信息
///这个函数应该启动一个线程用于不断得发送数据包信息
/// 当读取完文件后，取消前端的监听
#[tauri::command]
fn open_pcap_file(path:&str,bpf:&str,window:Window,offline_bank:State<Bank>)->Result<(),String>{
  let path = path.trim();
  dbg!("Start open file:{path}!");
  match Capture::from_file(path){
    Ok(mut cap) =>{
      match cap.filter(bpf, true){
          Ok(_) => {
            offline_bank.linktype.lock().unwrap().replace(cap.get_datalink());//记录链路类型
            let packets = offline_bank.packets.clone();
            thread::spawn(move ||{
              let new_linktype = cap.get_datalink();
              for (index,packet) in cap.iter(Codec).flatten().enumerate(){
                let _ = window.emit("Info", &packet.get_info(&new_linktype, index as u32));
                packets.lock().unwrap().push(packet);
              }
              //结束后发送一个Stop信号
              //没有负载
              let _ = window.emit("Stop", ());
            });
            dbg!("Open Success!");
          },
          Err(e) =>{
            dbg!("Filter Failed!");
            return Err(e.to_string());
          },
      }
    },
    Err(e) =>{
      dbg!("Open Failed!");
      return Err(e.to_string());
    }
  }
  //额外步骤，不应该影响正常流程
  //将文件列表更新
  if let Ok(files) = fs::read_to_string(FILE_LIST_PATH){
    let mut files:Vec<String> = files.split('\n').map(|s| s.trim().to_string()).collect();
    if !files.iter().any(|x| x.eq(path)){
      files.push(path.to_string());
      let mut file = fs::File::create(FILE_LIST_PATH).expect("Failed to create file!");
      file.write_all(files.join("\n").as_bytes()).expect("Failed to write file!");
    }
  }else{
    //创建文件列表
    let _ = fs::write(FILE_LIST_PATH,path);
  }
  Ok(())
}
#[tauri::command]
fn clear_bank(offline_bank:State<Bank>){
  offline_bank.packets.lock().unwrap().clear();
  offline_bank.packets.lock().unwrap().shrink_to_fit();
}
//在前端选中活跃的设备时被调用
//使用被选中的设备和Bpf创建一个活跃的Capture
//并在线程中不断的捕获数据包发往前端
#[tauri::command]
fn start_capture(bpf:String,devname:String,window:Window,active_bank:State<Bank>,cap_run:State<RunState>,cap_handle:State<ThreadState>)->Result<(),String>{
  if let Some(dev) = Device::list().map_err(|e|e.to_string())?.into_iter().find(|d| d.name.eq(&devname)){
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
      cap.filter(&bpf, true).map_err(|e|e.to_string())?;
      //应该在线程开始执行前将状态设置为true
      *cap_run.is_running.lock().unwrap() = true;
      let run_state = cap_run.is_running.clone();
      let mut codec = Codec{};
      let packets = active_bank.packets.clone();
      active_bank.linktype.lock().unwrap().replace(cap.get_datalink());
      let newhandle = thread::spawn(move ||{
        let mut index = 0;
        let linktype = cap.get_datalink();
        loop {
          if !(*run_state.lock().unwrap()){
            break;
          }
          if let Ok(packet) = cap.next_packet(){
            let new_packet = codec.decode(packet);
            let _ = window.emit("Info", &new_packet.get_info(&linktype, index));
            packets.lock().unwrap().push(new_packet);
            index+=1;
          }
        }
      });
      cap_handle.handle.lock().unwrap().replace(newhandle);
    }
  }
  dbg!("Start Capture Success!");
  Ok(())
}
#[tauri::command]
fn stop_thread(run:State<RunState>,handle:State<ThreadState>){
  if let Some(thread) = handle.handle.lock().unwrap().take(){
    *run.is_running.lock().unwrap() = false;
    thread.join().expect("Failed to join previous task!");
  }
  dbg!("Stop Capture Success!");
}
///只能在前端的Active页面被调用
///将活跃的Capture所捕获的数据包保存为文件
///并在file_list中添加该文件
///在前端调用StopCapture后，该函数才能被调用
#[tauri::command]
fn save_to_file(path:&str,active_bank:State<Bank>)->Result<(),String>{
  let packets = active_bank.packets.lock().unwrap();
  let cap = Capture::dead(Linktype(1)).map_err(|e| e.to_string())?;
  let mut save = cap.savefile(path).map_err(|e|e.to_string())?;
  for p in packets.iter(){
    save.write(&Packet{header:&p.header,data:&p.data});
  }
  save.flush().map_err(|e|e.to_string())?;

  //额外步骤，不应该影响正常流程
  if let Ok(files) = fs::read_to_string(FILE_LIST_PATH){
    let mut files:Vec<String> = files.split('\n').map(|s| s.trim().to_string()).collect();
    if !files.iter().any(|x| x.eq(path)){
      files.push(path.to_string());
      let mut file = fs::File::create(FILE_LIST_PATH).expect("Failed to create file!");
      file.write_all(files.join("\n").as_bytes()).expect("Failed to write file!");
    }
  }else{
    fs::File::create(FILE_LIST_PATH).expect("Failed to create file!");
  }
  Ok(())
}
/// 该函数必定返回成功，但不保证有数据
#[tauri::command]
fn get_file_list()->Vec<String>{
  let result = fs::read_to_string(FILE_LIST_PATH);
  if let Ok(files) = result{
    let mut new_file_list = Vec::<String>::new();
    let lines:Vec<String> = files.split('\n').map(|s| s.trim().to_string()).collect();
    lines.iter().for_each(|line| {
      let file_path = Path::new(&line);
      //file_path 的 end_with不可用
      // 检查文件是否存在
      if file_path.exists() && line.ends_with(".pcap"){
          new_file_list.push(line.clone());
      }
    });
    let mut file = fs::File::create(FILE_LIST_PATH).expect("Failed to create file!");
    file.write_all(new_file_list.join("\n").as_bytes()).expect("Failed to write file!");
    new_file_list
  }else {
    fs::File::create(FILE_LIST_PATH).unwrap();
    Vec::new()
  }
}
#[tauri::command]
fn get_detail(index:usize,bank:State<Bank>)->Vec<Protocal>{
  let linktype = bank.linktype.lock().unwrap().unwrap_or(Linktype::ETHERNET);
  bank.packets.lock().unwrap().get(index).unwrap().parse(&linktype,index as u32)
}
// #[tauri::command]
// fn get_linklayer(index:usize,offline_bank:State<Bank>)->Result<LinkLayer,UndecodeProtocal>{
//   //保证该函数被调用时，index不超过bank长度且bank不为空
//   offline_bank.data.lock().unwrap().get(index).unwrap().get_linklayer()
// }
// #[tauri::command]
// fn get_netlayer(index:usize,offline_bank:State<Bank>)->Option<Result<NetworkLayer,UndecodeProtocal>>{
//   //保证该函数被调用时，index不超过bank长度且bank不为空
//   offline_bank.data.lock().unwrap().get(index).unwrap().get_net_layer()
// }
// #[tauri::command]
// fn get_translayer(index:usize,offline_bank:State<Bank>)->Option<Result<TransformLayer,UndecodeProtocal>>{
//   //保证该函数被调用时，index不超过bank长度且bank不为空
//   offline_bank.data.lock().unwrap().get(index).unwrap().get_trans_layer()
// }