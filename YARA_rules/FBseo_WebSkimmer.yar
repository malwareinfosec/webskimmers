rule FBseo_WebSkimmer : Magecart WebSkimmer FBseo
{
    meta:
        author = "JS"
        description = "FBseo WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /\w\[\w\]=\s\w\[\w\];\w\[\w\]=\s\w;\w=\s\(\w\+\s\w\)%\s\d{7}/
    
    condition:
        $regex
}