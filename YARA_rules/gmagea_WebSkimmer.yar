rule gmagea_WebSkimmer : Magecart WebSkimmer gmagea
{
    meta:
        author = "JS"
        description = "gmagea WebSkimmer"
        reference = "https://twitter.com/killamjr/status/1185376383180136448"
        date = "2021-04-09"
    
    strings:
        $regex = /function\screateZxCScript/
    
    condition:
        $regex
}