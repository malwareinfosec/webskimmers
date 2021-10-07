rule Magento1x_WebSkimmer : Magecart WebSkimmer Magento1x
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (Magento1x)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://antoinevastel.com/fraud/2020/09/20/analyzing-magento-skimmer.html"
        date = "2021-10-07"
        
    strings:
        $regex = /(\-text\/javascript">|<script>)var\sa0a=\[/
    
    condition:
        $regex
}