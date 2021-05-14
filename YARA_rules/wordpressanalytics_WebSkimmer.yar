rule wordpressanalytics_WebSkimmer : Magecart WebSkimmer wordpressanalytics
{
    meta:
        author = "JS"
        description = "wordpressanalytics WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /a.id\s=\s"ecc1dbbb";/
    
    condition:
        $regex
}