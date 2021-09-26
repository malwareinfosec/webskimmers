rule Bom_WebSkimmer : Magecart WebSkimmer Bom
{
    meta:
        author = "@malwareinfosec"
        description = "Magecart (Bom)"
        reference = "https://community.riskiq.com/article/743ea75b"
        date = "2021-09-25"
        
    strings:
        $regex = /,urll,true\)/
		$regex2 = /;urll=\s_0x/
		$regex3 = /\];function\sboms\(\)/
		$regex4 = /stats:btoa\(_0x/
    
    condition:
        any of them
}