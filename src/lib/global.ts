import { writable,type Writable } from "svelte/store";
export let bpf_statement: Writable<string> = writable("");
export let bpf_isvalid:Writable<boolean> = writable(false);


//adapter and active use
export let active_dev_name: Writable<string> = writable("");
//choose_file and offline use 
export let offline_path: Writable<string> = writable("");

export function protocal2color(protocal:string):string{
    if(protocal == "TCP"){
        //return "background-color:#6195c6;color: rgb(235, 96, 54)"
        return "background-color:#6195c6;color: black"
    }else if(protocal == "UDP"){
        //return "background-color: #e68a8a;color: rgb(74, 208, 212);"
        return "background-color: #e68a8a;color: black;"
    }else if(protocal == "ICMP"){
        //return "background-color: #bcad91;color: rgb(169, 235, 141);"
        return "background-color: #bcad91;color: black;"
    }else if(protocal == "ICMPv6"){
        //return "background-color: #a1db97;color: rgb(238, 220, 130);"
        return "background-color: #a1db97;color: black;"
    }else if(protocal == "Arp"){
        //return "background-color: #d09deb;color: rgb(130, 238, 173);"
        return "background-color: #d09deb;color: black;"
    }else{
        return "background-color: white;color: black;"
    }
}