rule Radix_WebSkimmer : Magecart WebSkimmer Radix
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Radix)"
		source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://blog.sucuri.net/2019/03/more-on-dnsden-biz-swipers-and-radix-obfuscation.html"
        date = "2021-09-25"
        
    strings:
        $regex = /0a(0w){12}/
    
    condition:
        $regex
}