rule Magento_footer_WebSkimmer : Magecart WebSkimmer Magento_footer
{
    meta:
        author = "@malwareinfosec"
        description = "Magecart (Magento_footer)"
        reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/injecting-magecart-into-magento-global-config/"
        date = "2021-09-25"
        
    strings:
        $regex = /function\sFN2Z22\(\)\{var/
    
    condition:
        $regex
}