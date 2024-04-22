import { invoke } from "@tauri-apps/api";

export interface Protocal{
    name:string,
    header:Array<string>,
    payload:Uint8Array,
}
export async function get_protocals(index:number):Promise<Protocal[]>{
    return await invoke('get_detail',{index:index})
}