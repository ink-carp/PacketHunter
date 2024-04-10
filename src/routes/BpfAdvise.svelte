<script lang="ts">
    import { bpf_statement } from "$lib/global";
    let items = [
        { col1: 'tcp', col2: 'udp', col3: 'net' },
        { col1: 'host 127.0.0.1', col2: '...', col3: 'Item 6' },
        { col1: '0133' , col2:'151' ,col3:'1531'},
        { col1: '0133' , col2:'151' ,col3:'1531'}
        // 添加更多项...
    ];
    // 通过 store 更新 items
    function choose_item(bpf:string){
        bpf_statement.set(bpf);
    }
</script>

<table>
    <tbody>
        {#each items as advise}
            <tr>
                <td on:click={() => choose_item(advise.col1)}>{advise.col1}</td>
                <td on:click={() => choose_item(advise.col2)}>{advise.col2}</td>
                <td on:click={() => choose_item(advise.col3)}>{advise.col3}</td>
            </tr>
        {/each}
    </tbody>
</table>

<style>
    table {
        height: 100%;
        background-color: rgb(182, 230, 113);
        width: 100%;
        border-radius: 10px;
    }
    tbody{
        width: 100%;
        height: max-content;
    }
    tr {
        width: 100%;
        table-layout: fixed;
    }
    td {
        border-radius: 10px;
        width: 30%;
        padding: 10px;
        border: 1px solid #000000;
        background: linear-gradient(to right, #3498db, #8e44ad);
        transition: background-color 0.3s ease;
    }

    td:hover {
        background: linear-gradient(to left, #3498db, #8e44ad);
    }

    td:active {
        background: #2dd952;
    }
</style>