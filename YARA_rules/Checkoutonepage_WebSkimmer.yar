rule Checkoutonepage_WebSkimmer : Magecart WebSkimmer checkoutonepage
{
    meta:
        author = "JS"
        description = "checkoutonepage WebSkimmer"
        reference = "https://twitter.com/AffableKraut/status/1174933081792188416?s=20"
        date = "2021-04-06"
    
    strings:
        $regex = /'atob','(Y2hlY2tvdXQvb25lcGFnZQ|Y2hlY2tvdXQ)==?','getElement/
        $regex2 = /\(window.atob\("Y2hlY2tvdXQvb25lcGFnZQ==/
    
    condition:
        $regex or $regex2
}