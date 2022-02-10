rule heroku_WebSkimmer : Magecart WebSkimmer heroku
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (heroku)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://blog.malwarebytes.com/web-threats/2019/12/theres-an-app-for-that-web-skimmers-found-on-paas-heroku/"
        date = "2022-02-10"
        
    strings:
        $regex = /!function\(e,n,i\)\{function\st/
    
    condition:
        $regex
}