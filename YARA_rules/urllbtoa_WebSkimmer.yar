rule urllbtoa_WebSkimmer : Magecart WebSkimmer urllbtoa
{
    meta:
        author = "JS"
        description = "urllbtoa WebSkimmer"
        reference = "https://twitter.com/killamjr/status/1212058181725114369?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /url:urll,data:btoa/
    
    condition:
        $regex
}