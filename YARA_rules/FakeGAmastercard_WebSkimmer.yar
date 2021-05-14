rule FakeGAmastercard_WebSkimmer : Magecart WebSkimmer FakeGAmastercard
{
    meta:
        author = "JS"
        description = "FakeGAmastercard WebSkimmer"
        reference = "https://blog.malwarebytes.com/web-threats/2019/11/web-skimmer-phishes-credit-card-data-via-rogue-payment-service-platform/"
        date = "2021-04-09"
    
    strings:
        $regex = /if\(JSON\.stringify\(SendFlag\)\s==\sJSON\.stringify\(vals\)\)\{/
    
    condition:
        $regex
}