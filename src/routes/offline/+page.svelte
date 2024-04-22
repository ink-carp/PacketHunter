<script lang="ts">
  import { invoke } from '@tauri-apps/api/tauri';
  import {message} from '@tauri-apps/api/dialog';
  import { onMount,onDestroy } from 'svelte';
  import type { PacketInfo } from '$lib/class/info';
  //这里不引入bpf_isvalid，因为这里不需要检查bpf语句是否合法,在上一部分就检查过了
  import {offline_path,bpf_statement,protocal2color} from '$lib/global';
  import {goto} from '$app/navigation';
	import { writable, type Writable } from 'svelte/store';
	import { listen, once, type UnlistenFn } from '@tauri-apps/api/event';
  import type { Protocal } from '$lib/class/protocal';

  // 定义变量
  let unlisten:Promise<UnlistenFn> | null;
  let infos:Writable<Array<PacketInfo>> | null;
  let row_selcted:boolean = false;
  let protocals:Writable<Array<Protocal>> | null;
  let protocal_index:number | null;

  onMount(()=>{
    unlisten = null;
    protocals = writable([]);
    infos = writable([]);
    row_selcted = false;
    protocal_index = null;

    invoke('open_pcap_file',{path:$offline_path,bpf:$bpf_statement}).then((res)=>{
      unlisten = listen<PacketInfo>('Info',(event)=>{
        infos?.update((value)=>{
          value.push(event.payload);
          return value;
        });
      });
      once('Stop',()=>{
        unlisten?.then((fn)=>fn());
        unlisten = null;
      });
      console.debug('offline page mounted successfully!');
    }).catch((err)=>{
      console.debug('offline page mounted failed!');
      message(err.toString(),"error");
    });
  });
  onDestroy(()=>{
    invoke('clear_bank').catch((err)=>{
      console.error(err);
    });
    unlisten?.then((fn)=>fn());
    unlisten = null;
    infos = null;
    row_selcted = false;
    protocal_index = null;
    protocals = null;
    invoke('clear_bank');
    console.debug('offline page destroyed');
  });

  function select_row(index:number){
    invoke<Protocal[]>('get_detail',{index:index})
            .then((res)=>{
              protocals?.set(res);
              row_selcted = true;
              protocal_index = null;
            }).catch((err)=>{
              console.error(err);
    });
  }
</script>


<!-- 内容分为三部分 -->
<!-- 头部为文件信息 [返回按钮]  [当前捕获器:bpf] -->
<!-- 主体部分为表格，用于显示Info信息 -->
<!-- 底部为选中行的详细信息 -->
<header>
  <button on:click={() => goto('/choosefile')}>返回</button>
  <p>{$bpf_statement.length>0?"当前过滤器:"+$bpf_statement:"当前未使用任何过滤器"}</p>
</header>

<main>
{#if $infos}
  <table class="table">
    <thead>
      <tr>
        <th>序号</th>
        <th>来源</th>
        <th>目标</th>
        <th>长度</th>
        <th>捕获时间</th>
        <th>协议</th>
        <th>简要</th>
      </tr>
    </thead>
    <!-- 当且仅当infos有内容时才渲染 -->
    {#if $infos.length}
      <tbody>
        {#each $infos as row}
          <tr style="{protocal2color(row.finalprotocal)}" on:click={() => select_row(row.index)}>
            <td>{row.index}</td>
            <td>{row.source}</td>
            <td>{row.destination}</td>
            <td>{row.len}</td>
            <td>{row.time}</td>
            <td>{row.finalprotocal}</td>
            <td style="text-align:left">{row.info}</td>
          </tr>
        {/each}
      </tbody>
    {:else}
      <h2>没有内容</h2>
    {/if}
  </table>
{/if}
</main>

{#if row_selcted}
<footer>
	<div>
    {#if $protocals}
      {#each $protocals as protocal , index}
        <details>
          <summary on:click={()=>{protocal_index = index;}}>{protocal.name}</summary>
            {#each protocal.header as line}
              <p>{line}</p>
            {/each}
        </details>
      {/each}
    {/if}
	</div>
  <div>
    {#if protocal_index && $protocals}
      {$protocals[protocal_index].payload}
    {/if}
  </div>
</footer>
{/if}













<style>
  header{
		width: 90%;
    	height: 10%;
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding-left: 2.5%;
		padding-right: 2.5%;
		background-color: #f0f0f0;
		border-radius: 10px;
	}
	header button{
		width: 15%;
		padding: 5px 10px;
		border: 1px solid #ccc;
		border-radius: 5px;
		background-color: #f0f0f0;
	}
	header p{
		border: 1px solid #000;
		border-radius: 5px;
		width: 50%;
		text-align: center;
		font-size: 16px;
	}
  main{
    width: 95%;
    max-width: max-content;
    height: auto;
    max-height: 90%;
    overflow: auto;
  }
  footer{
		width: 95%;
		height: 20vh;
		display: flex;
		justify-content: space-between;
	}
	footer div{
		padding: auto;
		width: 45%;
		height: 100%;
		display: block;
		flex: 0 0 50%;
		flex-direction: column;
		line-height: 1.2;
		font-size: small;
		overflow-y: auto;
		overflow-wrap: break-word;
		box-sizing: border-box;
	}
	footer p{
		margin: 0;
		background-color: rgb(179, 224, 229);
	}
	details {
		border: 1px solid #000;
        border-radius: 4px;
        margin-bottom: 1em;
		padding: .5em;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    summary {
		user-select: none;
        font-size: 1.2em;
        color: #333;
        cursor: pointer;
    }

    summary:hover {
        background: linear-gradient(to left, #61e5d3, #e549d3);
    }

    summary::-webkit-details-marker {
        display: none;
    }
  /* 表格样式 */
  table {
    width: max-content;
    border-collapse: collapse;
    font-size: 15px;
  }

 /* 表格样式 */
 table {
		/* display: block;
		overflow-x: auto; */
		width: 100%;
		max-width: max-content;
		height: 100%;
		border-collapse: collapse;
		font-size: 15px;
		white-space: nowrap;
	}

	table th {
		background-color: #549fea;
		border: 1px solid #000000;
		padding: 8px;
		text-align: center;
		position: sticky;
		top: 0;
	}
	table td {
		border: 1px solid #ddd;
		padding: 8px;
		text-align: center;
	}
	table tr{
		transition: all 0.3s ease;
	}
	table tr:hover {
		transform: scaleY(1.1);
		background: linear-gradient(to left, #61e5d3, #e549d3 , #cfe53e);
	}

	table tr:active {
		transform: scaleY(0.9);
		transform: scaleX(0.95);
		background-color: rgb(238, 43, 235);
	}
  button {
    transition: all 0.3s ease;
  }

  button:hover {
    transform: scale(1.1);
    background-color: #1ac6d6;
  }

  button:active {
    transform: scale(0.9);
    background-color: rgb(211, 27, 201);
  }
</style>