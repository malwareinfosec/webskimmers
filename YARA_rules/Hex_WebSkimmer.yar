rule Hex_WebSkimmer : Magecart WebSkimmer Hex
{
    meta:
        author = "JS"
        description = "Hex WebSkimmer"
        reference = "https://twitter.com/killamjr/status/1207685407229526023?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /(\\)?x62(\\)?x69(\\)?x6[cC](\\)?x6[cC](\\)?x69(\\)?x6[eE](\\)?x67/
    
    condition:
        $regex
}