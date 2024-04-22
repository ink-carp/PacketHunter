<script lang="ts">
	import { goto } from "$app/navigation";
	import { invoke } from "@tauri-apps/api";
	import { ask, message, save } from "@tauri-apps/api/dialog";
    import { bpf_statement ,capture_status ,infolayer} from "$lib/global";
    import { InfoLayer } from "$lib/class/info";

    let save_state = false;
    let buttonText = '';
    let originalText = '';
    let layer:InfoLayer;
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
    function when_click_button(){
        if($capture_status){
            invoke('stop_thread')
            .then(()=>{
                capture_status.set(false);
            }).catch((err)=>{
                message(err.toString(),"error");
            });
        }else if(!save_state){
            save_file();
        }
    }
    function leave(path:string){
        if($capture_status){
            ask("抓包中，是否离开？","警告")
            .then((res)=>{
                if(res){
                    goto(path);
                }
            });
        }else if(!save_state){
            ask("抓包未保存，是否离开？","警告")
            .then((res)=>{
                if(res){
                    goto(path);
                }
            });
        }else{
            goto(path);
        }
    }
    $: {
        if ($capture_status) {
        buttonText = '停止';
        originalText = buttonText;
        } else if (!save_state) {
        buttonText = '保存';
        originalText = buttonText;
        } else {
        buttonText = '已停止';
        originalText = buttonText;
        }
    }
    $:{
        infolayer.set(layer);
    }
</script>

<header>
    <button on:click={when_click_button}>
        {buttonText}
    </button>
    <button type="button" on:click={()=>{leave('/count')}}>
        统计
    </button>
    <p>当前过滤器:{$bpf_statement}</p>
    <label>
        link
        <input type="radio" bind:group={layer} value={InfoLayer.link}>
    </label>
    <label>
        net
        <input type="radio" bind:group={layer} value={InfoLayer.net}>
    </label>
    <label>
        trans
        <input type="radio" bind:group={layer} value={InfoLayer.trans}>
    </label>
</header>
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
	button {
		width: auto;
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
</style>