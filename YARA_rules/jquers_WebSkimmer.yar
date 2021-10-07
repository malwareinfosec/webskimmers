rule jquers_WebSkimmer : Magecart WebSkimmer jquers
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (jquers)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/jeromesegura/status/1137087208630833152?s=20"
        date = "2021-10-07"
        
    strings:
        $regex = /localStorage.removeItem\('__'\+s1\+'123'\)/
    
    condition:
        $regex
}