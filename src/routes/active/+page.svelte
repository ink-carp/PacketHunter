<script lang="ts">
	import { invoke } from '@tauri-apps/api/tauri';
	import { listen ,type UnlistenFn } from '@tauri-apps/api/event';
	import { message ,save ,ask } from '@tauri-apps/api/dialog';
	import { goto } from '$app/navigation';
	import {bpf_statement, active_dev_name, protocal2color} from '$lib/global';
	import { writable, type Writable } from 'svelte/store';
	import { onMount,onDestroy } from 'svelte';
	import {type PacketInfo } from '$lib/class/info';
	import {type Protocal } from '$lib/class/protocal';

	let infos:Writable<PacketInfo[]> | null;
	let protocals:Writable<Protocal[]> | null;
	let unlisten:Promise<UnlistenFn>|null;
	let capture_status:boolean;
	let save_state:boolean;
	let row_selcted:boolean;
	let protocal_index:number | null;

	onMount(()=>{
		infos = writable([]);
		protocals = writable([]);
		unlisten = null;
		capture_status = false;
		save_state = false;
		row_selcted = false;
		protocal_index = null;
		
		invoke('start_capture',{bpf:$bpf_statement , devname:$active_dev_name})
		.then(()=>{
			capture_status = true;
			console.debug('active page mounted successfully!');
		}).catch((err)=>{
			console.debug('active page mounted failed!');
			message(err.toString(),"error");
		});
		unlisten = listen<PacketInfo>('Info', (event) => {
			infos?.update((data) => {
				data.push(event.payload);
				return data;
			});
		});
	});
	onDestroy(()=>{
		invoke('stop_thread').catch((err)=>{
			console.error(err);
		});
		invoke('clear_bank').catch((err)=>{
			console.error(err);
		});
		if(unlisten){
			unlisten.then(fn => fn());
		}
		unlisten = null;
		row_selcted = false;
		capture_status = false;
		save_state = false;
		infos = null;
		protocals = null;
		protocal_index = null;
	});

	async function save_file(){
		const file_path = await save({
			filters: [
				{ name: '', extensions: ['pcap'] }
			],
			title:'请选择保存路径'
		});
		if(file_path){
			invoke('save_to_file',{path:file_path})
			.then(()=>{
				message("保存成功","success");
				save_state = true;
			}).catch((err)=>{
				message(err.toString(),"error");
			});
		}
	}
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

<!-- 页面头部显示 [保存按钮] [当前的Filter语句] [返回按钮] -->
<header>
	{#if capture_status}
		<button on:click={()=>{invoke('stop_thread');capture_status = false;}}>停止</button>
	{:else if !save_state && $infos && $infos.length > 0}
		<button on:click={() =>{save_file();}}>保存</button>
	{:else}
		<button disabled>结束</button>
	{/if}
	<p>{$bpf_statement.length > 0?"当前Filter:"+$bpf_statement:"没有应用过滤器"}</p>
	<button on:click={()=>{
		if(capture_status){
			invoke('stop_thread');
		}
		if(!save_state && $infos && $infos.length > 0){
			ask("是否保存当前数据包?","提示").then((res)=>{
				if(res){
					save_file().then(()=>{
						goto("/adapters");
					})
				}else{
					goto("/adapters");
				}
			});
		}else{
			goto("/adapters");
		}
		}}>返回</button>
</header>
<!-- 页面主体显示Info表格 -->
{#if $infos && $infos.length > 0}
<main>
	<table>
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
		<tbody>
			{#each $infos as row}
			<!-- svelte-ignore missing-declaration -->
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
	  </table>
</main>
{/if}
<!-- 页脚根据选择的行显示数据包具体信息 -->
{#if row_selcted && !capture_status}
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
		overflow-x: auto;
		height: auto;
		padding: 0;
		max-height: 90%;
		border-radius: 10px;
	}
	footer{
		width: 95%;
		min-height: 20vh;
		max-height: 20vh;
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
	button {
		user-select: none;
		transition: all 0.3s ease;
	}

	button:hover {
		transform: scale(1.1);
		background-color: #1fd1e1;
	}

	button:active {
		transform: scale(0.9);
		background-color: rgb(238, 43, 235);
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
</style>

