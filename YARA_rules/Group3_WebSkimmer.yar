rule Group3_WebSkimmer : Magecart WebSkimmer Group3
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Group3)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://community.riskiq.com/projects/48b09759-49f9-c1a9-d1bb-dee04ae6155e"
        date = "2022-02-10"
        
    strings:
        $regex = /\\x73\\x65\\x74\\x69\\x64\\x64/
    
    condition:
        $regex
}