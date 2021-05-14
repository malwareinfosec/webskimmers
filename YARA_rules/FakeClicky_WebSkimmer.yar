rule FakeClicky_WebSkimmer : Magecart WebSkimmer FakeClicky
{
    meta:
        author = "JS"
        description = "FakeClicky WebSkimmer"
        reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"
        date = "2021-04-09"
    
    strings:
        $regex = /=','script','Y2hlY2tvdXQ=',/
    
    condition:
        $regex
}