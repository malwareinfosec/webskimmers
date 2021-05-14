rule gate_WebSkimmer : Magecart WebSkimmer gate
{
    meta:
        author = "JS"
        description = "gate WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /'CVV':null,'Gate':/
    
    condition:
        $regex
}