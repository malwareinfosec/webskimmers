rule AWS_WebSkimmer : Magecart WebSkimmer AWS
{
    meta:
        author = "JS"
        description = "AWS S3 WebSkimmer"
        reference = "https://twitter.com/killamjr/status/1184480414947139584?s=20"
        date = "2021-04-06"
    
    strings:
        $regex = /','\\x55\\x32\\x46\\x32\\x5[aA]\\x56\\x42\\x68\\x63\\x6[dD]\\x46\\x74',/
    
    condition:
        $regex
}