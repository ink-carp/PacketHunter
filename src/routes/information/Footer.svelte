<script lang="ts">
	import type { Protocal } from "$lib/class/protocal";
    import { select_row } from "$lib/global";
	import { invoke } from "@tauri-apps/api";
    let protocals:Promise<Protocal[]>;
    async function get_detail(index:number):Promise<Protocal[]>{
        return invoke<Protocal[]>('get_detail',{index:index});
    }
    $:{
        if($select_row >= 0){
            protocals = get_detail($select_row);
        }
    }
</script>




<!-- 页脚根据选择的行显示数据包具体信息 -->
{#if $select_row >= 0}
{#await protocals}
    正在加载...
{:then items} 
    <footer>
        {#if items}
            <div>
            {#each items as protocal}
                <details>
                <summary>{protocal.name}</summary>
                    {#each protocal.header as line}
                    <p>{line}</p>
                    {/each}
                </details>
            {/each}
            </div>
        {/if}
        {#if items.length > 0 && items[items.length-1].payload && items[items.length-1].payload.length > 0}
            <div>
                <p>数据包内容:</p>
                <p>{items[items.length-1].payload?.reduce((acc,cur)=>acc+cur.toString(16).padStart(2,'0')+" ",'')}</p>
            </div>
        {/if}
    </footer>
{/await}
{/if}

<style>
    footer{
		width: 95%;
		height: 20vh;
		display: flex;
		justify-content: space-between;
	}
	footer div{
		padding: auto;
		width: 100%;
		min-width: 45%;
		height: 100%;
		display: block;
		/* flex: 0 0 50%; */
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
</style>