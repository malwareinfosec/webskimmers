rule css_WebSkimmer : Magecart WebSkimmer css
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (css)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/AvastThreatLabs/status/1496428689944371202"
        date = "2022-02-23"
        
    strings:
        $regex = /\}(\t){3}\n(\t){2}\s(\t){2}(\n){2}\t\n\t/
		$regex2 = /'POST',decodeURIComponent\(escape\(\w{2,8}\)\),!0\);\w{2,8}\.send\(null\);\}/
    
    condition:
        $regex or $regex2
}
