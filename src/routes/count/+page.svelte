<script lang="ts">
    import { onDestroy, onMount } from 'svelte';
    import { Chart, LineController, CategoryScale, LinearScale, PointElement ,LineElement} from 'chart.js';
	import { invoke } from '@tauri-apps/api';
	import { message } from '@tauri-apps/api/dialog';
    interface PacketCount {
        total: number,
        protocal_and_number_count: { [key: string]: number },
        ip_source_count: { [key: string]: number },
        ip_destination_count: { [key: string]: number },
        mac_source_count: { [key: string]: number },
        mac_destination_count: { [key: string]: number },
        port_source_count: { [key: string]: number },
        port_destination_count: { [key: string]: number },
        flow_count_by_second: Uint32Array, // 索引值就是时间顺序,统计每秒的流量
        size_count: Uint32Array, // 索引值就是大小 *10 ,超过1000kB的都算在1000kB
    }
    Chart.register(LineController, CategoryScale, LinearScale, PointElement,LineElement);
    Chart.defaults.font.family = 'Arial';
    Chart.defaults.font.size = 16;
    Chart.defaults.color = '#333';

    let count:PacketCount | null = null;
    let chart: Chart | null = null;
    let flowcanvas:any;
    let sizecanvas:any;
    onMount(() => {
        invoke<PacketCount>('get_count').then((res) => {
            count = res;
            console.debug("获取统计信息成功");

            // 创建图表
            if (flowcanvas instanceof HTMLCanvasElement) {
                const ctx = flowcanvas.getContext('2d');
                if (ctx) {
                    chart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: Array.from({length: count.flow_count_by_second.length}, (_, i) => i + 1),
                            datasets: [{
                                label: 'Flow Count by Second',
                                data: Array.from(count.flow_count_by_second),
                                fill: false,
                                borderColor: 'rgb(75, 192, 192)',
                                tension: 0.1
                            }]
                        },
                        options: {
                            plugins: {
                                title: {
                                    display: true,
                                    text: '每秒流量统计' // 添加图表标题
                                }
                            },
                            scales: {
                                x: {
                                    title: {
                                        display: true,
                                        text: '时间(s)' // 添加 x 轴单位
                                    }
                                },
                                y: {
                                    title: {
                                        display: true,
                                        text: '流量(Bytes)' // 添加 y 轴单位
                                    }
                                }
                            }
                        }
                    });
                }
            }
            if (sizecanvas instanceof HTMLCanvasElement) {
                const ctx = sizecanvas.getContext('2d');
                if (ctx) {
                    chart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: Array.from({length: count.size_count.length}, (_, i) => i + 1),
                            datasets: [{
                                label: 'Flow Count by Second',
                                data: Array.from(count.size_count),
                                fill: false,
                                borderColor: 'rgb(75, 192, 192)',
                                tension: 0.1
                            }]
                        },
                        options: {
                            plugins: {
                                title: {
                                    display: true,
                                    text: '数据包大小和数量统计' // 添加图表标题
                                }
                            },
                            scales: {
                                x: {
                                    title: {
                                        display: true,
                                        text: '数据包大小 (100bytes)' // 添加 x 轴单位
                                    }
                                },
                                y: {
                                    title: {
                                        display: true,
                                        text: '数量' // 添加 y 轴单位
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }).catch((err) => {
            message('获取统计信息失败:'+err, {title: '错误', type: 'error'});
        });
    });
    onDestroy(() => {
        count = null;
        if (chart) {
            chart.destroy();
            chart = null;
        }
        invoke('clear_count').then(() => {
            console.debug("关闭统计成功");
        }).catch((err) => {
            console.error("关闭统计失败:"+err);
        });
    });
</script>
<main>
    
{#if count}
<h1>抓取的数据包数量: {count.total}</h1>
<div>
    <ul>
        <p>协议和数量统计</p>
        {#each Object.entries(count.protocal_and_number_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
    <ul>
        <p>源IP统计</p>
        {#each Object.entries(count.ip_source_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
    <ul>
        <p>目的IP统计</p>
        {#each Object.entries(count.ip_destination_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
</div>
<div>
    <ul>
        <p>源MAC统计</p>
        {#each Object.entries(count.mac_source_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
    <ul>
        <p>目的MAC统计</p>
        {#each Object.entries(count.mac_destination_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
    <ul>
        <p>源端口统计</p>
        {#each Object.entries(count.port_source_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
    <ul>
        <p>目的端口统计</p>
        {#each Object.entries(count.port_destination_count) as [key, value]}
            <li>{key}: {value}</li>
        {/each}
    </ul>
</div>
{/if}
<canvas bind:this={flowcanvas}></canvas>
<canvas bind:this={sizecanvas}></canvas>
</main>


<style>
     @keyframes gradient {
        0% {
            background-position: 0% 50%;
        }
        50% {
            background-position: 100% 50%;
        }
        100% {
            background-position: 0% 50%;
        }
    }

    main {
        border: 2px black solid;
        width: 95vw;
        border-radius: 10px;
        display: flex;
        flex-direction: column;
        align-items: center;
        row-gap: 10px;
        background: linear-gradient(270deg, #abd06b, #af7483, #83b8bc);
        background-size: 600% 600%;
        animation: gradient 15s ease infinite;
    }
    canvas {
        width: 100%;
        height: 25%;
    }
    div {
        padding: 10px;
        margin: 0;
        gap: 10px;
        /* border: 2px black solid;
        border-radius: 5px; */
        max-width: max-content;
        display: flex;
        flex-direction: row;
    }

    ul {
        padding: 10px;
        padding-right: 20px;
        margin: 0;
        border: 2px black solid;
        border-radius: 5px;
        overflow-y: auto;
        height: 20vh;
        width: 30vw;
        max-width: max-content;
        scrollbar-width: thin; /* Firefox */
        scrollbar-color: rgba(155, 155, 155, 0.7) transparent; /* Firefox */
    }
    ul li {
        margin-bottom: 3px;
        padding: 3px;
        border: 1px solid black;
        border-radius: 5px;
    }

    ul li:hover {
        border: 1px solid red;
    }
    ul::-webkit-scrollbar {
        width: 12px;
    }

    ul::-webkit-scrollbar-track {
        background: transparent;
    }

    ul::-webkit-scrollbar-thumb {
        background-color: rgba(108, 195, 197, 0.7);
        border-radius: 20px;
        border: 3px solid transparent;
    }

     
</style>