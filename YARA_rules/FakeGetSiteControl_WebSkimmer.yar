rule FakeGetSiteControl_WebSkimmer : Magecart WebSkimmer FakeGetSiteControl
{
    meta:
        author = "JS"
        description = "FakeGetSiteControl WebSkimmer"
        reference = ""
        date = "2021-04-09"
    
    strings:
        $regex = /break;\n\}(\n)?\}\)\(window, document, '_gscq/
    
    condition:
        $regex
}