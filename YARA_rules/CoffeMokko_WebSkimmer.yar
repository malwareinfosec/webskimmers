rule CoffeMokko_WebSkimmer : Magecart WebSkimmer CoffeMokko
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (CoffeMokko)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://blog.group-ib.com/coffemokko"
        date = "2021-09-25"
        
    strings:
        $string = "/a/g,_$_"
		$string2 = "/h/g,_$_"
		$string3 = "/e/g,_$_"
		$string4 = "/0/g,_$_"
    
    condition:
        all of them
}