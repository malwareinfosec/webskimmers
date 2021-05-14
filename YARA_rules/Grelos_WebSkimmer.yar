rule Grelos_WebSkimmer : Magecart WebSkimmer Grelos
{
    meta:
        author = "JS"
        description = "Grelos WebSkimmer"
        reference = "https://twitter.com/killamjr/status/1209165822939279365?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /var grelos_v=/
    
    condition:
        $regex
}