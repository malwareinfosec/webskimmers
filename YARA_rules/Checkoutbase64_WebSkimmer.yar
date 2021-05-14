rule Checkoutbase64_WebSkimmer : Magecart WebSkimmer checkoutbase64
{
    meta:
        author = "JS"
        description = "checkoutbase64 WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /'YXRvYg==','WTJobFkydHZkWFE9'/
    
    condition:
        $regex
}