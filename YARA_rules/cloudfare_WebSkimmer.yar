rule cloudfare_WebSkimmer : Magecart WebSkimmer cloudfare
{
    meta:
        author = "JS"
        description = "cloudfare WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /\(function\(\)\n\{\n\tfunction\sOx\$/
    
    condition:
        $regex
}