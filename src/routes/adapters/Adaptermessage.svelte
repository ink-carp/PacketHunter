<script lang="ts">
    export let ipv4: string | null;
    export let ipv6: string | null;
    export let style = '';
</script>

<div style={style}>
    {#if ipv4 == null && ipv6 == null}
        <p>No IP address</p>
    {/if}
    {#if ipv4 != null}
        <p>IPv4: {ipv4}</p>
    {/if}
    {#if ipv6 != null}
        <p>IPv6: {ipv6}</p>
    {/if}
</div>

<style>
    div {
        position: absolute;
        background-color: #12e2d5;
        border: 1px solid #0a0a0a;
        border-radius: 10px;
        padding: 0px;
        /* z-index: 100; */
        height: min-content;
        width: 200px;
        pointer-events: none;
        font-size: small;
        line-height: 0px;
    }
</style>