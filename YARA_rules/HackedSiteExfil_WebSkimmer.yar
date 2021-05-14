rule HackedSiteExfil_WebSkimmer : Magecart WebSkimmer HackedSiteExfil
{
    meta:
        author = "JS"
        description = "HackedSiteExfil WebSkimmer"
        reference = "https://twitter.com/unmaskparasites/status/1186745552358252544?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /,urll,(false|true)\);/
    
    condition:
        $regex
}