rule grelos_WebSkimmer : Magecart WebSkimmer grelos
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (grelos)"
		source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/killamjr/status/1209165822939279365?s=20"
        date = "2021-09-25"
        
    strings:
        $regex = /function\sFN2Z22\(\)\{var/
    
    condition:
        $regex
}