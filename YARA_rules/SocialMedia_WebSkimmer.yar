rule SocialMedia_WebSkimmer : Magecart WebSkimmer SocialMedia
{
    meta:
        author = "JS"
        description = "SocialMedia WebSkimmer"
        reference = "https://sansec.io/research/svg-malware"
        date = "2021-04-09"
    
    strings:
        $regex = /[iI]d=?\(?"(facebook|google|twitter|instagram|youtube|pinterest)_full"(\sviewbox="0\s0|\);window\.q=e)/
    
    condition:
        $regex
}