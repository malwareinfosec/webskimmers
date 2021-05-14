rule Inter_WebSkimmer : Magecart WebSkimmer Inter
{
    meta:
        author = "JS"
        description = "Inter WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /\$[sr].SaveAllFields\(\);\r?\n\n?\s{8}\$[sr].GetCCInfo\(\);/
    
    condition:
        $regex
}