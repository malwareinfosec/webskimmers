rule ATMZOW_WebSkimmer : Magecart WebSkimmer ATMZOW
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (ATMZOW skimmer)"
		source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/AffableKraut/status/1174933081792188416?s=20"
        date = "2021-09-25"
        
    strings:
        $regex = /0a(0w){12}/
    
    condition:
        $regex
}