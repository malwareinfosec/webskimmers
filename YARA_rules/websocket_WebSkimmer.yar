rule websocket_WebSkimmer : Magecart WebSkimmer websocket
{
    meta:
        author = "JS"
        description = "websocket WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /"w".concat\('ss',\s":"\)\)/
    
    condition:
        $regex
}