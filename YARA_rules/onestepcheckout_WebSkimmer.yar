rule onestepcheckout_WebSkimmer : Magecart WebSkimmer onestepcheckout
{
    meta:
        author = "JS"
        description = "onestepcheckout WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /window.atob\("b25lc3RlcGNoZWNrb3V0"\)/
    
    condition:
        $regex
}