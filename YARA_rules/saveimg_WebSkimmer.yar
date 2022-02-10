rule saveimg_WebSkimmer : Magecart WebSkimmer saveimg
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (saveimg)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = ""
        date = "2022-02-10"
        
    strings:
        $regex = /dG9rZW58c2VhcmNofGNzZnJ8a2V5d29yZHxidXR0b24/
    
    condition:
        $regex
}