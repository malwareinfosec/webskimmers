rule CoffeMokko_WebSkimmer : Magecart WebSkimmer CoffeMokko
{
    meta:
        author = "JS"
        description = "CoffeMokko WebSkimmer"
        reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /if\(location.href.search\(atob\("ZmlyZWNoZWNrb3V0"\)\)!=-1/
    
    condition:
        $regex
}