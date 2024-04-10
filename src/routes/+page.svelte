<script>
	import welcome from '$lib/images/svelte-welcome.webp';
	import welcome_fallback from '$lib/images/svelte-welcome.png';
    import {goto} from '$app/navigation';
</script>

<svelte:head>
	<title>Home</title>
	<meta name="description" content="Packet Hunter Home Page" />
</svelte:head>

<section>
	<span class="welcome">
		<picture>
			<source srcset={welcome} type="image/webp" />
			<img src={welcome_fallback} alt="Welcome" />
		</picture>
	</span>
	<h1 class="masked">To Packet Hunter</h1>
</section>
<main>
    <button on:click={()=>{goto('/adapters')}}>
        <span class="new">
            创建新的监听
        </span>
    </button>
    <button on:click={()=>{goto('/choosefile')}}>
        <span class="old">
            读取已有文件
        </span>
    </button>
</main>


<style>
	section {
        width: 95%;
        height: 75%;
		display: flex;
		flex-direction: column;
		justify-content: center;
		align-items: center;
	}
    main{
        width: 95%;
        height: 25%;
        display: flex;
        justify-content: space-between;
        margin-bottom: 5vh;
    }
	.welcome {
		display: block;
		position: relative;
		width: 100%;
		height: 50%;
        margin: 0;
        padding: 0;
	}

	.welcome img {
		position: absolute;
		width: 100%;
		height: 100%;
		top: 0;
		display: block;
        user-select: none;
	}
    .masked{
        margin: 0;
        padding: 0;
        font-size: calc(5vw + 5vh);
        user-select: none;
        text-align: center;
        background-image: -webkit-linear-gradient(left, #292a3a, #536976 25%, #67d741 50%,  #a1c4fd, #c2e9fb);
        -webkit-text-fill-color: transparent;
        -webkit-background-clip: text;
        -webkit-background-size: 200% 100%;
        -webkit-animation: masked-animation 2s infinite linear;
       
    }
    @-webkit-keyframes masked-animation {
            0%{ background-position: 0 0;}
            100% { background-position: -100% 0;}
    }
    
    button {
        display: inline-block;
        border-radius: 10vw;
        background :linear-gradient(135deg, #c850c0, #4158d0);
        border: none;
        color: linear-gradient(135deg, #292a3a, #536976);
        padding: 5%;
        width:40%;
        transition: all 0.5s;
        cursor: pointer;
        margin: 5px;
        user-select: none;
        align-items: center;
    }
    button span {
        height: 100%;
        width: 100%;
        font-size: calc(2vw + 2vh);
        cursor: pointer;
        text-align: center;
        position: relative;
        transition: 0.5s;
    }
    button span.new::before{
        content: '\00ab';  /* CSS Entities. 如果用的是 HTML Entities, 请改成 &#8594;*/
        position: absolute;
        opacity: 0;
        top: 0;
        left: -1vw;
        transition: 0.5s;
    }
    button:hover span.new::before {
        opacity: 1;
        left: 0;
    }
    button:hover span.new {
        padding-left: 5vw;
    }
    button span.old::after{
        content: '\00bb';  /* CSS Entities. 如果用的是 HTML Entities, 请改成 &#8594;*/
        position: absolute;
        opacity: 0;
        top: 0;
        right: -1vw;
        transition: 0.5s;
    }
    button:hover span.old {
        padding-right: 5vw;
    }
    button:hover span.old:after {
        opacity: 1;
        right: 0;
    }
</style>