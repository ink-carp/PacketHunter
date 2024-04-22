<script lang="ts">
    import { bpf_statement } from "$lib/global";
    let items = [
        { col1: 'tcp', col2: 'udp', col3: 'net $ip/$mask' },
        { col1: 'host $ip', col2: 'port $port', col3: 'icmp' },
        { col1: 'tcp and port 80' , col2:'src' ,col3:'dst'},
        { col1: 'ip', col2: 'arp', col3: 'rarp' },
        { col1: 'less $length', col2: 'greater $length', col3: 'ip6' },
        { col1: 'ether src $mac', col2: 'ether dst $mac', col3: 'ether host $mac' },
        { col1: 'ip src $ip', col2: 'ip dst $ip', col3: 'ip host $ip' },
        { col1: 'tcp src port $port', col2: 'tcp dst port $port', col3: 'tcp port $port' },
        { col1: 'udp src port $port', col2: 'udp dst port $port', col3: 'udp port $port' },
        { col1: 'icmp[icmptype] == icmp-echo', col2: 'icmp[icmptype] == icmp-echoreply', col3: 'icmp[icmptype] == icmp-unreach' }
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