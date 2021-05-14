rule jj_WebSkimmer : Magecart WebSkimmer jj
{
    meta:
        author = "JS"
        description = "jj WebSkimmer"
        reference = "https://twitter.com/unmaskparasites/status/1377382029709348864?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /_jj\['c'\+'v'\+'v'/
    
    condition:
        $regex
}