import { writable, type Writable } from "svelte/store";

export interface PacketInfo{
    index:number,
    len:number,
    caplen:number,
    time:string,
    linkinfo:HeaderInfo,
    netinfo:HeaderInfo,
    transinfo:HeaderInfo,
}
export interface HeaderInfo{
    source:string,
    destination:string,
    protocal:string,
    info:string,
}
export enum Mode{
    active,
    offline,
}
export enum InfoLayer{
    link,
    net,
    trans
}