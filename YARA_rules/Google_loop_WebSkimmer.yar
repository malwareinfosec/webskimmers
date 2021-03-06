rule Google_loop_WebSkimmer : Magecart WebSkimmer Google_loop
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Google loop)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/AffableKraut/status/1261157021027622912?s=20"
        date = "2021-09-25"
        
    strings:
        $regex = /l1l1<userID\.length;l1l1\+\+/
    
    condition:
        $regex
}