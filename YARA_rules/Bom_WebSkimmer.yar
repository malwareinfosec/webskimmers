rule Bom_WebSkimmer : Magecart WebSkimmer Bom
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Bom)"
         source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://community.riskiq.com/article/743ea75b"
        date = "2021-09-25"
        
    strings:
        $regex = /,urll,true\)/
        $regex2 = /;urll=\s_0x/
        $regex3 = /\];function\sboms\(\)/
        $regex4 = /stats:btoa\(_0x/
		$regex5 = /\]\](\(|=\s)_0x\w{1,8}(\[\d{1,2}\]|\))\}\}\}setInterval\(/
    
    condition:
        any of them
}