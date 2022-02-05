rule cloudvideo_WebSkimmer : Magecart WebSkimmer cloudvideo
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (cloudvideo)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://unit42.paloaltonetworks.com/web-skimmer-video-distribution/"
        date = "2022-02-04"
        
    strings:
        $string = "restoreFirstVideojs"
        $string2 = "VHJ5U2VuZA"
    
    condition:
        $string or $string2
}