rule grelos_WebSkimmer : Magecart WebSkimmer grelos
{
    meta:
        author = "@malwareinfosec"
        description = "Magecart (grelos)"
        reference = "https://twitter.com/killamjr/status/1209165822939279365?s=20"
        date = "2021-09-25"
        
    strings:
        $regex = /var grelos_v=/
    
    condition:
        $regex
}