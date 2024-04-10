export interface Adapter{
    connected:boolean,
    wireless:boolean,
    name:string;
    description:string,
    ipv4:string | null,
    ipv6:string | null
}
export interface Stream{
    name:string,
    receive:number,
    drop:number
}
export interface Flow{
    nets:Stream[]
}