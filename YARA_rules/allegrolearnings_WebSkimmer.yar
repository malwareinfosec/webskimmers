rule allegrolearnings_WebSkimmer : Magecart WebSkimmer allegrolearnings
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (allegrolearnings)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/MBThreatIntel/status/1242538048044150784?s=20"
        date = "2021-10-07"
        
    strings:
        $regex = /var\srx_one\s=\s\/\^\[\\\],:\{\}\\s\]\*\$\/;/
    
    condition:
        $regex
}