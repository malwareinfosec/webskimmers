rule state_skimmer_WebSkimmer : Magecart WebSkimmer state_skimmer
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (state skimmer)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = ""
        date = "2021-09-25"
        
    strings:
        $regex = /return\(!!window\[\w{2}\(/
        $regex2 = /\w\(\)&&console\[/
    
    condition:
        all of them
}