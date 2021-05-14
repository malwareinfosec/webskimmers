rule Callback_WebSkimmer : Magecart WebSkimmer Callback
{
    meta:
        author = "JS"
        description = "Callback WebSkimmer"
        reference = "https://twitter.com/AffableKraut/status/1225279882118209536?s=20"
        date = "2021-04-06"
    
    strings:
        $regex = /\s{12}_script\("[0-9a-z]{74}"\),|_scriptCallback\s=\s"[0-9a-z]{1000}/
    
    condition:
        $regex
}