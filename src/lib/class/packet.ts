export interface PacketInfo{
    index:number,
    source:string,
    destination:string,
    len:number,
    time:string,
    finalprotocal:string,
    info:string,
}
export interface UndecodeProtocal{
    protocal_name:String,
    payload:Uint8Array,
}