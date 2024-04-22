<script lang="ts">
	import Header from "./Header.svelte";
	import Footer from "./Footer.svelte";
	import VirtualScroll from "svelte-virtual-scroll-list";

	import {active_device, bpf_statement, offline_path, packets_limit ,capture_status, select_row ,infolayer} from "$lib/global";
    import {InfoLayer, type PacketInfo } from "$lib/class/info";
	import { listen, once, type UnlistenFn } from "@tauri-apps/api/event";
	import { invoke } from "@tauri-apps/api";
	import { message} from "@tauri-apps/api/dialog";
	import { onDestroy, onMount } from "svelte";





    let items:PacketInfo[] = [];
    let unlisten:Promise<UnlistenFn> | null = null;

	onMount(()=>{
		//初始化
		capture_status.set(false);
		select_row.set(-1);
		infolayer.set(InfoLayer.link);
		//监听数据包
		if($active_device.length){
			invoke('start_capture',{devname:$active_device,bpf:$bpf_statement,limit:$packets_limit})
			.then(()=>{
				capture_status.set(true);
				unlisten = listen<PacketInfo>('Info',(info)=>{
					items = [...items,info.payload];
				});
				once('Stop',()=>{
					if(unlisten){
						unlisten.then((fn)=>{
							fn();
						});
					}
					capture_status.set(false);
				});
			}).catch((err)=>{
				message(err.toString(),"error");
			});
		}else if($offline_path.length){
			invoke('open_pcap_file',{path:$offline_path,bpf:$bpf_statement})
			.then(()=>{
				capture_status.set(true);
				unlisten = listen<PacketInfo>('Info',(info)=>{
					items = [...items,info.payload];
				});
				once('Stop',()=>{
					if(unlisten){
						unlisten.then((fn)=>{
							fn();
						});
					}
					capture_status.set(false);
				});
			}).catch((err)=>{
				message(err.toString(),"error");
			});
		}
	});
	onDestroy(()=>{
		invoke('stop_thread');
		invoke('clear_bank');
		if(unlisten){
			unlisten.then((fn)=>{
				fn();
			});
		}
		capture_status.set(false);
		active_device.set('');
		offline_path.set('');
		bpf_statement.set('');
		packets_limit.set(1024);
		select_row.set(-1);
		infolayer.set(InfoLayer.link);
	});
</script>

<!-- 抓取启动成功时才显示 -->
<Header></Header>
<main>
	<div class="table">
		<div class="row">
			<div >序号</div>
			<div >长度</div>
			<div >包长</div>
			<div >时间</div>
			<div >源地址</div>
			<div >目的地址</div>
			<div >协议</div>
			<div >数据包摘要</div>
		</div>
		<VirtualScroll data={items} key="index" let:data>
			<div class="row"  on:click={()=>{select_row.set(data.index);}}
				on:keydown={(event)=>{if(event.key === 'Enter' || event.key === ' ') select_row.set(data.index);}}
				role="button"
				tabindex="0">
				<div >{data.index}</div>
				<div >{data.len}</div>
				<div >{data.caplen}</div>
				<div >{data.time}</div>
				{#if $infolayer == InfoLayer.link}
				<div >{data.linkinfo.source}</div>
				<div >{data.linkinfo.destination}</div>
				<div >{data.linkinfo.protocal}</div>
				<div >{data.linkinfo.info}</div>
				{:else if $infolayer == InfoLayer.net}
				<div >{data.netinfo.source}</div>
				<div >{data.netinfo.destination}</div>
				<div >{data.netinfo.protocal}</div>
				<div >{data.netinfo.info}</div>
				{:else if $infolayer == InfoLayer.trans}
				<div >{data.transinfo.source}</div>
				<div >{data.transinfo.destination}</div>
				<div >{data.transinfo.protocal}</div>
				<div >{data.transinfo.info}</div>
				{/if}
			</div>
		</VirtualScroll>
	</div>
</main>
<Footer></Footer>




<style>
	main{
		width: 95%;
		height: 60%;
		margin-bottom: 2.5%;
	}
	.table {
        border: 1px solid black;
        border-radius: 10px;
        height: 100%;
        width: 100%;
        display: flex;
        flex-direction: column;
    }

    .row {
		padding: 0;
		margin: 0;
		height: 7.5%;
		width: 100%;
        display: flex;
		flex-wrap: nowrap;
		overflow: none;
		font-size: small;
		transition: background 0.3s ease;
    }
	.row:hover {
        background: linear-gradient(to right, #7ad7df, #c596e3); /* Change this to the colors you want on hover */
    }

    .row:active {
        background: linear-gradient(to right, #e39fe2, #82dde0); /* Change this to the colors you want on click */
    }

    .row > :nth-child(1) {
        flex: 0.5;
        border: 1px solid #ccc;
        padding: 10px;
    }
    .row > :nth-child(2) {
        flex: 0.5;
        border: 1px solid #ccc;
        padding: 10px;
    }
    .row > :nth-child(3) {
        flex: 0.5;
        border: 1px solid #ccc;
        padding: 10px;
    }
	.row > :nth-child(4) {
        flex: 2;
        border: 1px solid #ccc;
        padding: 10px;
    }
	.row > :nth-child(5) {
        flex: 1.5;
        border: 1px solid #ccc;
        padding: 10px;
    }
	.row > :nth-child(6) {
        flex: 1.5;
        border: 1px solid #ccc;
        padding: 10px;
    }
	.row > :nth-child(7) {
        flex: 1;
        border: 1px solid #ccc;
        padding: 10px;
    }
    .row > :nth-child(8) {
        flex: 3;
        border: 1px solid #ccc;
        padding: 10px;
    }
	

</style>