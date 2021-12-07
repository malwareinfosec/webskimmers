rule tagmanager2_WebSkimmer : Magecart WebSkimmer tagmanager2
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (tagmanager2)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://geminiadvisory.io/magecart-google-tag-manager/"
        date = "2021-12-06"
        
    strings:
        $regex = /typeof\s\$s!==a0_0x\w{6}\((0x\w{1,5},){3}0x\w{1,5}\)&&\(\$s\[a0_0x/
        $regex2 = /window\[a0_0x\w{3,12}\((0x\w{2,6},){3}(0x\w{2,6})\)\]\)\)new\sself/
    
    condition:
        $regex or $regex2
}