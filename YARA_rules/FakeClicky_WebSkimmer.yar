rule FakeClicky_WebSkimmer : Magecart WebSkimmer FakeClicky
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (FakeClicky)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"
        date = "2021-09-25"
        
    strings:
        $regex = /=','script','Y2hlY2tvdXQ=/
    
    condition:
        $regex
}