<script lang="ts">
    import { invoke } from '@tauri-apps/api/tauri';
    import { listen ,type UnlistenFn} from '@tauri-apps/api/event';
    import {onMount,onDestroy} from 'svelte'
    import Bpf from '../Bpf.svelte';
    import Adaptermessage from './Adaptermessage.svelte';
    import type {Adapter,Stream} from '$lib/class/adapter';
	import { message } from '@tauri-apps/api/dialog';
    import {goto} from '$app/navigation';
    import { bpf_statement ,bpf_isvalid, active_dev_name } from '$lib/global';
    import { writable } from 'svelte/store';





    //用于取消监听
    let unlisten:Promise<UnlistenFn>|null = null;

    // 创建一个可写 store adapters，并将空数组作为初始值传递给它
    let adapters = writable([] as Adapter[]);
    let showAdapterMessage = false;
    let ipv4:string | null;
    let ipv6:string | null;
    let mouseX = 0;
    let mouseY = 0;
    let adapterMessagePosition = 'right';
    let timer:number | null = null;
    const windowWidth = window.innerWidth;
    const windowHeight = window.innerHeight;


    function when_mouse_over(event:MouseEvent|FocusEvent, v4:string|null, v6:string|null) {
        ipv4 = v4;
        ipv6 = v6;
        if(event instanceof MouseEvent){
            mouseX = event.clientX;
            mouseY = event.clientY;

            if (windowWidth - mouseX < 200) {
                adapterMessagePosition = 'left';
            }else if (windowHeight - mouseY < 200) {
                adapterMessagePosition = 'top';
            }else {
                adapterMessagePosition = 'right';
            }
            showAdapterMessage = true;
        }else if (event instanceof FocusEvent){
            const rect = (event.target as HTMLElement).getBoundingClientRect();
            mouseX = rect.left + rect.width/2;
            mouseY = rect.top + rect.height/2;
            if (windowWidth - mouseX < 200) {
                adapterMessagePosition = 'left';
            }else if (windowHeight - mouseY < 200) {
                adapterMessagePosition = 'top';
            }else {
                adapterMessagePosition = 'right';
            }
            showAdapterMessage = true;
        }
    }
    function when_mouse_ignore(){
        clearTimeout(timer?timer:0);
        showAdapterMessage = false;
    }
    function when_dbclick(name:string,isactive:boolean){
        if(isactive&&$bpf_isvalid){
            active_dev_name.set(name);
            goto("/active");
        }else if(!$bpf_isvalid && !isactive){
            message("适配器不在活跃状态\nBpf语句不合法\n请选择正确的适配器和合法的Bpf语句后重试","warning").then().catch();
        }else if (!isactive){
            message("适配器不在活跃状态\n请选择活跃状态的设配器后重试","warning").then().catch();
        }else{
            message("Bpf语句不合法\n请使用正确的Bpf语句后重试","warning").then().catch();
        }
    }

    // 当 getAdapter 函数获取到新的 devices 后，更新 adapters 的值
    function getAdapter() {
        console.debug("get_adapter!");
        if(unlisten){
            unlisten.then((fn) => {
                fn();
            }).catch((err) => {
                console.error(err);
            });
        }
        invoke('get_device').then((message) => {
            adapters.update(() => message as Adapter[]);
            unlisten =  listen<[Stream]>('Flow', (event) => {
                    for(const stream of event.payload){
                        const row = document.getElementById(stream.name);
                        const receive = row?.querySelector("#receive") as HTMLElement;
                        if(receive){
                            receive.innerText = stream.receive.toString();
                        }
                        const drop = row?.querySelector("#drop") as HTMLElement;
                        if(drop){
                            // console.log(stream.drop);
                            drop.innerText = stream.drop.toString();
                        }
                    }
            });
        }).catch((err) => {
            console.error(err);
        });
    }
    onMount(() => {
        bpf_statement.set("");
		bpf_isvalid.set(true);
        getAdapter();
        console.debug("Adapter initialized!");
    });
    onDestroy(() =>{
        invoke('stop_thread').catch(() => {
            console.error('Error stopping send');
        });
        if (unlisten){
            unlisten.then((ok) =>{
                ok();
                unlisten = null;
            }).catch((err) =>{
                console.error(err);
            });
         };
        unlisten = null;
        adapters.set([]);
        showAdapterMessage = false;
        ipv4 = null;
        ipv6 = null;
        mouseX = 0;
        mouseY = 0;
        adapterMessagePosition = 'right';
        timer = null;
        console.debug("Adapter Destroyed!");
    });
</script>













{#if showAdapterMessage}
    <Adaptermessage bind:ipv4 bind:ipv6 style="top: {mouseY}px; left: {mouseX}px; transform: {adapterMessagePosition === 'left' ? 'translateX(-100%)' : adapterMessagePosition === 'top' ? 'translateY(-100%)' : 'none'};"></Adaptermessage>
{/if}
<header>
    <button class="adapter-bt" on:click={getAdapter}>刷新适配器</button>
    <div style="width: 80% ;height:75%;padding-right:5vw">
        <Bpf></Bpf>
    </div>
</header>
{#if adapters}
    <table id="AdaptersList">
        <!-- <caption>
            适配器列表
        </caption> -->
        <thead>
            <tr>
            <th>活动状态</th>
            <th>名称</th>
            <th>介绍</th>
            <th>类型</th>
            <th>接收</th>
            <th>丢包</th>
            </tr>
        </thead>
        <tbody>
            {#each $adapters as row}
            <tr 
                on:mouseenter={(event) => { timer = setTimeout(() => when_mouse_over(event,row.ipv4,row.ipv6), 500);}}
                on:mouseleave="{when_mouse_ignore}" 
                on:focus={(event) => when_mouse_over(event,row.ipv4,row.ipv6)} 
                on:blur="{when_mouse_ignore}"
                on:dblclick={() => when_dbclick(row.name,row.connected)}
                id={row.name}>
                <td><div class="toggle-icon-{row.connected?'on':'off'}"></div></td>
                <td>{row.name}</td>
                <td>{row.description}</td>
                <td>{row.wireless ? "无线" : "Online"}</td>
                <td id="receive"></td>
                <td id="drop"></td>
            </tr>
            {/each}
        </tbody>
    </table>
{:else}
  <h1>请点击按钮获取网络设备列表</h1>
{/if}














<style>
header{
    width: 95%;
    height: 10%;
    margin: 5px;
    padding: 5px;
    display: flex;
    flex-direction: row;
    align-items: center;
}
.adapter-bt{
    width: 20%;
    height: 100%;
    margin: 10px 10px;
    font-size: 16px;
    background-color: #4CAF50;
    color: white;
    border: none;
    border-radius: 5ch;
    cursor: pointer;
    transition: transform 0.3s ease, background-color 0.3s ease; /* 添加动画 */
}

.adapter-bt:hover {
    background-color: #45a049; /* 悬停时的背景颜色 */
}

.adapter-bt:active {
    transform: scale(0.95); /* 点击时的缩放效果 */
}

    
table {
    overflow-y: auto; /* 使用滚动条 */
    border-collapse: separate;
    border-spacing: 0;
    width: 95%;
    height: 85%;
    padding-left: 2.5%;
    padding-right: 2.5%;
    max-width: max-content;
    font-family: Arial, sans-serif; /* 使用Arial字体 */
    color: #000000; /* 文字颜色 */
    background: #ffffff; /* 背景颜色 */
    margin: 20px 0; /* 上下边距 */
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.15); /* 添加阴影 */
    border-radius: 5px;
}
thead th{
    background-color: #f2f2f2;
    font-weight: bold;
    text-transform: uppercase; /* 文字转为大写 */
    color: #333; /* 文字颜色 */
    padding: 5px;
    margin: 5px;
    text-align: center;
}
thead th:first-child {
    border-top-left-radius: 5px;
}
thead th:last-child {
    border-top-right-radius: 5px;
}
tbody tr:last-child td:first-child {
    border-bottom-left-radius: 5px;
}
tbody tr:last-child td:last-child {
    border-bottom-right-radius: 5px;
}
tbody tr {
    height: 10%;
    border: 1px solid transparent; /* 添加透明边框 */
    user-select: none;
    transition: background-color 0.3s ease; /* 添加动画 */
}
tbody tr:hover {
    background-color: #a390906b; /* 悬停时的背景颜色 */
}
tbody td{
    padding: 5px;
    text-align: center;
}
tbody{
    overflow-y: scroll;
}

.toggle-icon-off {
    width: 20px;
    height: 20px;
    position: relative;
    background-color: #cd5454;
    border-radius: 50%;
    display: inline-block;
}
.toggle-icon-on {
    width: 20px;
    height: 20px;
    position: relative;
    background-color: #11c857;
    border-radius: 50%;
    display: inline-block;
}

</style>