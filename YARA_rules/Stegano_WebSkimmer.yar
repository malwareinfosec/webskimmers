rule Stegano_WebSkimmer : Magecart WebSkimmer Stegano
{
    meta:
        author = "JS"
        description = "Stegano WebSkimmer"
        reference = "https://twitter.com/AffableKraut/status/1210298763417276416?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /new\sFunction\s?\(this.responseText.slice\(-[0-9]{5}\)\)/
    
    condition:
        $regex
}