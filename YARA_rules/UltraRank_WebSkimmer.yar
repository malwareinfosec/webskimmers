rule UltraRank_WebSkimmer : Magecart WebSkimmer UltraRank
{
    meta:
        author = "JS"
        description = "UltraRank WebSkimmer"
        reference = "https://www.group-ib.com/blog/ultrarank"
        date = "2021-04-09"
    
    strings:
        $regex = /var\sJ8X="M9/
    
    condition:
        $regex
}