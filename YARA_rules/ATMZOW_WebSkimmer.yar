rule ATMZOW_WebSkimmer : Magecart WebSkimmer ATMZOW
{
    meta:
        author = "JS"
        description = "ATMZOW WebSkimmer"
        reference = "https://twitter.com/AffableKraut/status/1174933081792188416?s=20"
        date = "2021-04-06"
        
    strings:
        $regex = /0a(0w){12}/
    
    condition:
        $regex
}