rule state_loader_WebSkimmer : Magecart WebSkimmer state_loader
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (state loader)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = ""
        date = "2021-09-25"
        
    strings:
        $regex = /"load",function\(\)\{\(function\(\)\{/
        $regex2 = /while\(!!\[\]\)\{try{var/
        $regex3 = /\(\w\['shift'\]\(\)\);\}\}\}/
    
    condition:
        all of them
}