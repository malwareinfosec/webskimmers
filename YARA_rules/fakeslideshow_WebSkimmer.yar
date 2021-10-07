rule fakeslideshow_WebSkimmer : Magecart WebSkimmer fakeslideshow
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (fakeslideshow)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/AffableKraut/status/1445043970283905024?s=20"
        date = "2021-10-07"
        
    strings:
        $regex = /\['105O110O112O117O116O','115O101O108O101O99O116O'/
    
    condition:
        $regex
}