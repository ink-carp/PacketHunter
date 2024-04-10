<script lang="ts">
  // 导入
  import { invoke } from '@tauri-apps/api/tauri';
  import { open ,message } from '@tauri-apps/api/dialog';
  import { onMount,onDestroy } from 'svelte';
  import Bpf from '../Bpf.svelte';
	import {bpf_isvalid,bpf_statement,offline_path} from '$lib/global';
	import BpfAdvise from '../BpfAdvise.svelte';
  import {goto} from '$app/navigation';
  
  // 定义变量
  let file_list:string[] | null;

  // 函数定义
  //通过按钮触发
  async function get_path_by_button(){
    const selected = await open({
    multiple: false,
    filters: [{
        name: '',
        extensions: ['pcap']
      }]
    });
    //selected不会为数组
   if(bpf_isvalid){
    if (Array.isArray(selected)) {
      // user selected multiple files
    } else if (selected === null) {
      // user cancelled the selection
    } else {
      offline_path.set(selected);
      goto("/offline").then(()=>{console.log("goto offline")});
    }
   }else{
      await message("BPF语句不合法","warning");
   }
  }
  function get_path_by_list(path:string){
    offline_path.set(path);
    goto("/offline").then(()=>{console.log("goto offline")});
  }
  onMount(()=>{
    bpf_statement.set("");
		bpf_isvalid.set(true);
    invoke<string[]>("get_file_list").then((res) => {
      if (res) {
        file_list = res;
      }
    }).catch((e)=>{
      message(e.toString(),"error");
    });
    console.log("Choosefile Initialized!");
  });
  onDestroy(()=>{
    file_list=null;
    console.log("Choosefile Destroyed!");
  });
</script>

<!-- 页面内容 -->
<!-- 页面应该被分为上下两部分 -->
<!-- 上部分为bpf和常用bpf语句列表 -->

<!-- 下部分为文件选择，分为文件列表和文件选择按钮 -->
<header>
  <div>
    <BpfAdvise></BpfAdvise>
  </div>
  <div>
    <Bpf></Bpf>
  </div>
</header>
<footer>
  {#if file_list}
    <ul class="file-list">
    {#each file_list as path}
    <li class="file-list-item" on:dblclick={() =>{get_path_by_list(path)}}>{path}</li>
    {/each}
    </ul>
  {:else}
    <p>没有历史文件，请打开新文件</p>
  {/if}
</footer>
<button on:click={get_path_by_button}>{file_list?'打开其他文件':'打开文件'}</button>
<!-- 样式定义 -->
<style>
  header{
    height: 40%;
    width: 95%;
    display: flex;
    flex-direction: column;
  }
  header div:first-child {
    height: 70%; 
    overflow-y: auto;
    margin-bottom: 5px;
  }

  header div:last-child {
    height: 20%;  
    margin-bottom: 5px;
  }
  footer{
    width: 95%;
    height: 40%;
    overflow-y: auto;
  }
  .file-list {
    display:list-item;
    list-style-type: none;
    padding: 0;
  }

  .file-list-item {
    user-select: none;
    margin-bottom: 0; /* 调整项目之间的垂直间距 */
    padding: 10px; /* 添加填充以增加点击区域 */
    border: 1px solid #ccc; /* 添加边框 */
    border-radius: 5px; /* 添加圆角 */
    cursor: pointer; /* 显示指针样式 */
    transition: background-color 0.3s; /* 添加过渡效果 */
    background: linear-gradient(to right, #f14cd8, #1654c6);
    color: white;
  }
  .file-list-item:hover {
    background: linear-gradient(to right,  #1654c6,#f14cd8); /* 鼠标划过时的背景色 */
  }

  .file-list-item:active {
    background: #98f1b3; /* 点击时的背景色 */
  }
  button {
    margin-top: 10px;
    width: 95%;
    height: 10%;
    background: linear-gradient(to right, #358aca, #c5e31b);
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s; /* 添加过渡效果 */
  }

  button:hover {
    background: linear-gradient(to right, #c5e31b, #358aca); /* 鼠标悬停时的背景色 */
  }

  button:active {
    background: #98f1b3; /* 点击时的背景色 */
  }
</style>
