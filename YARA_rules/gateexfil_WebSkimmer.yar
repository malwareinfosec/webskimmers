rule gateexfil_WebSkimmer : Magecart WebSkimmer gateexfil
{
    meta:
        author = "JS"
        description = "gateexfil WebSkimmer"
        reference = "https://twitter.com/killamjr/status/1210663057547882496?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /0x19[a-z]'\),\r\n\s{4}'Gate':/
    
    condition:
        $regex
}