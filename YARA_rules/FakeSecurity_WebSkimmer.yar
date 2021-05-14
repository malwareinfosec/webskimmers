rule FakeSecurity_WebSkimmer : Magecart WebSkimmer FakeSecurity
{
    meta:
        author = "JS"
        description = "FakeSecurity WebSkimmer"
        reference = "https://www.group-ib.com/blog/fakesecurity_raccoon"
        date = "2021-04-09"
    
    strings:
        $regex = /\)\)\s\('_'\);$/
    
    condition:
        $regex
}