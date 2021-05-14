rule MagentoFooter_WebSkimmer : Magecart WebSkimmer MagentoFooter
{
    meta:
        author = "JS"
        description = "MagentoFooter WebSkimmer"
        reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/injecting-magecart-into-magento-global-config/"
        date = "2021-04-09"
    
    strings:
        $regex = /function\sFN2Z22\(\)\{var/
    
    condition:
        $regex
}