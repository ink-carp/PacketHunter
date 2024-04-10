<script lang="ts">
  import { invoke } from '@tauri-apps/api/tauri';
  import {message} from '@tauri-apps/api/dialog';
  import { onMount,onDestroy } from 'svelte';
  import type { PacketInfo } from '$lib/class/packet';
  import { type LinkLayer ,link_parser,link_payload} from '$lib/class/linklayer';
  import { type NetworkLayer ,net_parser,net_payload} from '$lib/class/netlayer';
  import { type TransformLayer ,trans_parser, trans_payload} from '$lib/class/translayer';
  import { type UndecodeProtocal } from '$lib/class/packet';
  //这里不引入bpf_isvalid，因为这里不需要检查bpf语句是否合法,在上一部分就检查过了
  import {offline_path,bpf_statement} from '$lib/global';
  import {goto} from '$app/navigation';

  // 定义变量
  let infos:PacketInfo[] | null;
  let row_selcted:boolean = false;
  let link:LinkLayer | null;
  let net:NetworkLayer | null;
  let trans:TransformLayer | null;
  let undecode_link:UndecodeProtocal | null;
  let undecode_net:UndecodeProtocal | null;
  let undecode_trans:UndecodeProtocal | null;



  function get_offline_detail(row_index:number){
    invoke<LinkLayer>('get_offline_linklayer',{index:row_index})
    .then((res)=>{
      link = res;
      undecode_link = null;
    })
    .catch((err)=>{
      link = null;
      undecode_link = err as UndecodeProtocal;
    });
    invoke('get_offline_netlayer',{index:row_index})
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
    invoke('get_offline_translayer',{index:row_index})
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
  onMount(()=>{
    invoke<PacketInfo[]>('open_pcap_file',{path:$offline_path,bpf:$bpf_statement}).then((res)=>{
      infos = res;
    }).catch((err)=>{
      message(err.toString(),"error");
    });
    console.log('offline page mounted');
  });
  onDestroy(()=>{
    infos = null;
    row_selcted = false;
    link = null;
    net = null;
    trans = null;
    undecode_link = null;
    undecode_net = null;
    undecode_trans = null;
    invoke('clear_offline_bank');
    console.log('offline page destroyed');
  });
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
{#if infos}
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
    {#if infos.length > 0}
      <tbody>
        {#each infos as row}
          <tr on:click={() => get_offline_detail(row.index)}>
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
    width: 70%;
    text-align: center;
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
  /* 表格样式 */
  table {
    width: max-content;
    border-collapse: collapse;
    font-size: 15px;
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