rule svg_WebSkimmer : Magecart WebSkimmer svg
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (svg)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://sansec.io/research/svg-malware"
        date = "2021-09-25"
        
    strings:
        $regex = /[iI]d=?\(?"(facebook|google|twitter|instagram|youtube|pinterest)_full"(\sviewbox="0\s0|\);window\.q=e)/
    
    condition:
        $regex
}