rule simple_WebSkimmer : Magecart WebSkimmer simple_skimmer
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (simple skimmer)"
		source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/AffableKraut/status/1399786791931101192"
        date = "2021-09-25"
        
    strings:
        $re1 = /=\s\["change",\s"\[name=cc_cvv2\]",/
        $s1 = "post"
        $s2 = "ready"
    
    condition:
        all of them
}