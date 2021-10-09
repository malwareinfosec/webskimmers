rule Q_logger_WebSkimmer : Magecart WebSkimmer Q_logger
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Q_logger)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://twitter.com/AffableKraut/status/1385030485676544001?s=20"
        date = "2021-09-25"
        
    strings:
        $regex = /var\s\w=\{isOpen:!1,orientation:void\s0,detectInterval:null\}/
		$regex2 = /window\.addEventListener\("load",function\(\)\{\(function\(\)/
		$regex3 = /\]&&clearInterval\(\w\[\w{1,2}\([\w',\(\)\+\[\];\s\{\}\-!&\$\#\"]{10,200}/
    
    condition:
        any of them
}