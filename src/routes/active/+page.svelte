<script lang="ts">
	import { invoke } from '@tauri-apps/api/tauri';
	import { listen ,type UnlistenFn } from '@tauri-apps/api/event';
	import { message ,save ,ask } from '@tauri-apps/api/dialog';
	import { goto } from '$app/navigation';
	import {bpf_statement, active_dev_name, bpf_isvalid} from '$lib/global';
	import { writable, type Writable } from 'svelte/store';
	import { onMount,onDestroy } from 'svelte';
	import {type PacketInfo,type UndecodeProtocal } from '$lib/class/packet';
	import {link_parser, link_payload, type LinkLayer } from '$lib/class/linklayer';
	import {net_parser, net_payload, type NetworkLayer } from '$lib/class/netlayer';
	import {trans_parser, trans_payload, type TransformLayer } from '$lib/class/translayer';

	let received_data:Writable<PacketInfo[]> = writable([] as PacketInfo[]);
	let unlisten:Promise<UnlistenFn>|null = null;
	let capture_status:boolean = false;
	let save_state:boolean = false;

	let row_selcted:boolean = false;
	let link:LinkLayer | null;
	let net:NetworkLayer | null;
	let trans:TransformLayer | null;
	let undecode_link:UndecodeProtocal | null;
	let undecode_net:UndecodeProtocal | null;
	let undecode_trans:UndecodeProtocal | null;





	function get_active_detail(row_index:number){
		invoke<LinkLayer>('get_active_linklayer',{index:row_index})
		.then((res)=>{
			link = res;
			undecode_link = null;
		})
		.catch((err)=>{
			link = null;
			undecode_link = err as UndecodeProtocal;
		});
		invoke('get_active_netlayer',{index:row_index})
		.then((res:any)=>{
		if(res){
			const result = res as {Ok?: NetworkLayer, Err?: UndecodeProtocal};
			if(result.Ok){
				net = result.Ok;
				undecode_net = null;
			} else if(result.Err) {
				undecode_net = result.Err;
				net = null;
			}
		}
		})
		.catch(()=>{
			undecode_net = null;
			net = null;
		});
		invoke('get_active_translayer',{index:row_index})
		.then((res:any)=>{
		if(res){
			const result = res as {Ok?: TransformLayer, Err?: UndecodeProtocal};
			if(result.Ok){
				trans = result.Ok;
				undecode_trans = null;
			} else if(result.Err) {
				trans = null;
				undecode_trans = result.Err;
			}
		}
		})
		.catch(()=>{
			undecode_trans = null;
			trans = null;
		});
		row_selcted = true;
	}
	function start_listen(){
		invoke('start_capture',{bpf:$bpf_statement , devname:$active_dev_name})
		.then(()=>{
			capture_status = true;
		}).catch((err)=>{
			message(err.toString(),"error");
		});
		unlisten = listen<PacketInfo>('active', (event) => {
			received_data.update((data) => {
				data.push(event.payload);
				return data;
			});
		});
	}
	async function save_file(){
		const file_path = await save({
			defaultPath: 'packet_hunter',
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

	onMount(()=>{
		start_listen();
	});
	onDestroy(()=>{
		invoke('stop_capture');
		if(unlisten){
			unlisten.then(fn => fn());
		}
		unlisten = null;
		row_selcted = false;
		received_data.set([]);
		capture_status = false;
		save_state = false;
		link = null;
		net = null
		trans = null;
	});
</script>

<!-- 页面头部显示 [保存按钮] [当前的Filter语句] [返回按钮] -->
<header>
	{#if capture_status}
		<button on:click={()=>{invoke('stop_capture');capture_status = false;}}>停止</button>
	{:else if !save_state&&$received_data.length > 0}
		<button on:click={() =>{save_file();}}>保存</button>
	{:else}
		<button disabled>结束</button>
	{/if}
	<p>{$bpf_statement.length > 0?"当前Filter:"+$bpf_statement:"没有应用过滤器"}</p>
	<button on:click={()=>{
		if(capture_status){
			invoke('stop_capture');
		}
		if(!save_state){
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
{#if $received_data.length > 0}
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
		{#each $received_data as row}
			<tr on:click={() => get_active_detail(row.index)}>
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
		{#if link}
		  <p>链路层:</p>
		  {#each link_parser(link) as line}
			<p>{line}</p>
		  {/each}
		{:else}
		  {"链路层解析失败，协议:"+undecode_link?.protocal_name}
		{/if}
		{#if net}
		  <p>网络层:</p>
		  {#each net_parser(net) as line}
			<p>{line}</p>
		  {/each}
		{:else}
		  {"网络层解析失败，协议:"+undecode_net?.protocal_name}
		{/if}
		{#if trans}
		  <p>传输层:</p>
		  {#each trans_parser(trans) as line}
			<p>{line}</p>
		  {/each}
		{:else}
		  {"传输层解析失败，协议:"+undecode_trans?.protocal_name}
		{/if}
		</div>
		<div>
		  {#if link}
			{link_payload(link)}
		  {:else}
			{undecode_link?.payload}
		  {/if}
		  {#if net}
			{net_payload(net)}
		  {:else}
			{undecode_net?.payload}
		  {/if}
		  {#if trans}
			{trans_payload(trans)}
		  {:else}
			{undecode_trans?.payload}
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
		height: 20vh;
		display: flex;
		justify-content: space-between;
	}
	footer div{
		padding: auto;
		width: 45%;
		height: 100%;
		display: flex;
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
	}
	button {
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
</style>

