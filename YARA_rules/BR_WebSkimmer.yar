rule BR_WebSkimmer : Magecart WebSkimmer BR
{
    meta:
        author = "JS"
        description = "BR WebSkimmer"
        reference = ""
        date = "2021-04-06"
    
    strings:
        $regex = /\\x27\\x6E\\x75\\x6D\\x65\\x72\\x6F\\x5F\\x63\\x61\\x72\\x74\\x61\\x6F\\x27/
    
    condition:
        $regex
}