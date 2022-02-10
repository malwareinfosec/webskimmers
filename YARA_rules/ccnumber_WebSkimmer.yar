rule ccnumber_WebSkimmer : Magecart WebSkimmer ccnumber
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (ccnumber)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = ""
        date = "2022-02-10"
        
    strings:
        $regex = /(\\)?x63(\\)?x63(\\)?x5[fF](\\)?x6E(\\)?x75(\\)?x6[dD](\\)?x62(\\)?x65(\\)?x72/
    
    condition:
        $regex
}