rule Googleloop_WebSkimmer : Magecart WebSkimmer Googleloop
{
    meta:
        author = "JS"
        description = "Googleloop WebSkimmer"
        reference = "https://twitter.com/AffableKraut/status/1261157021027622912?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /l1l1<userID\.length;l1l1\+\+/
    
    condition:
        $regex
}