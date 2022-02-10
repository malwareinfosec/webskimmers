rule Inter_WebSkimmer : Magecart WebSkimmer Inter
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Inter)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://community.riskiq.com/article/30f22a00"
        date = "2022-02-10"
        
    strings:
        $regex = /GetCCInfo:(\s|)function\(\)/
    
    condition:
        $regex
}