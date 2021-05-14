rule Angular_WebSkimmer : Magecart WebSkimmer Angular
{
    meta:
        author = "JS"
        description = "Angular skimmer"
    
    strings:
        $regex = /\};Angular(\['|\.)ready('\])?\(\)|Angular\.algularToken|\}\}return null;\},'register':function\(_/
        
    condition:
        $regex
}