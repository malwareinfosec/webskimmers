rule CoffeMokko_WebSkimmer : Magecart WebSkimmer CoffeMokko
{
    meta:
        author = "@malwareinfosec"
        description = "Magecart (Google loop)"
        reference = "https://blog.group-ib.com/coffemokko"
        date = "2021-09-25"
        
    strings:
        $regex = /\w\[\w\]=\s\w\[\w\];\w\[\w\]=\s\w;\w=\s\(\w\+\s\w\)%\s\d{7}/
    
    condition:
        $regex
}