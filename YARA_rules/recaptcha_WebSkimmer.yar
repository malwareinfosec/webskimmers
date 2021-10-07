rule jquers_WebSkimmer : Magecart WebSkimmer recaptcha
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (recaptcha)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/sansecio/status/1445747878404583430?s=20"
        date = "2021-10-07"
        
    strings:
        $regex = /acqew\.lhrxk/
    
    condition:
        $regex
}