export interface Protocal{
    name:string,
    header:Array<string>,
    payload:Uint8Array | null,
}