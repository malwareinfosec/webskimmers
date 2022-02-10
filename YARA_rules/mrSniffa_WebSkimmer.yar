rule mrSniffa_WebSkimmer : Magecart WebSkimmer mrSniffa
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (mrSniffa)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/MBThreatIntel/status/1268982125543387136?s=20"
        date = "2022-02-10"
        
    strings:
        $regex = /var\seventsListenerPool\s=\sdocument.createElement\('script'\);/
    
    condition:
        $regex
}