import { writable,type Writable } from "svelte/store";
export let bpf_statement: Writable<string> = writable("");
export let bpf_isvalid:Writable<boolean> = writable(false);


//adapter and active use
export let active_dev_name: Writable<string> = writable("");
//choose_file and offline use 
export let offline_path: Writable<string> = writable("");

