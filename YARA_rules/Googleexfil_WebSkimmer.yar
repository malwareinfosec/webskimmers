rule Googleexfil_WebSkimmer : Magecart WebSkimmer Googleexfil
{
    meta:
        author = "JS"
        description = "Googleexfil WebSkimmer"
        reference = "https://twitter.com/AffableKraut/status/1362429457932419078?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /'replace','IMG','CVV'/
    
    condition:
        $regex
}