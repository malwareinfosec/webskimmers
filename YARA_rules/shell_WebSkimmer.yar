rule shell_WebSkimmer : Magecart WebSkimmer shell
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (shell)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://blog.malwarebytes.com/cybercrime/2021/05/newly-observed-php-based-skimmer-shows-ongoing-magecart-group-12-activity/"
        date = "2021-09-25"
        
    strings:
        $regex = /\$AJegUupT=/
    
    condition:
        $regex
}