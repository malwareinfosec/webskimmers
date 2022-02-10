rule shoplift_WebSkimmer : Magecart WebSkimmer shoplift
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (shoplift)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://www.foregenix.com/blog/credit-card-hijack-magento-javascript-alert"
        date = "2022-02-10"
        
    strings:
        $regex = /\+inp\[i\]\.value\+['"]&['"]/
    
    condition:
        $regex
}