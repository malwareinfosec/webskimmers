rule recaptcha_WebSkimmer : Magecart WebSkimmer recaptcha
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (recaptcha)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/MBThreatIntel/status/1452690744544665601"
        date = "2021-10-07"
        
    strings:
        $regex = /window\["JSON"\]\["parse"\]\(window\["atob"\]\(\w{3,8}\.\w{3,8}\)\);/
    
    condition:
        $regex
}