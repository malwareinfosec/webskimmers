rule Magento1x_WebSkimmer : Magecart WebSkimmer Magento1x
{
    meta:
        author = "JS"
        description = "Magento1x WebSkimmer"
        reference = "https://antoinevastel.com/fraud/2020/09/20/analyzing-magento-skimmer.html"
        date = "2021-04-09"
    
    strings:
        $regex = /(\-text\/javascript">|<script>)var\sa0a=\[/
    
    condition:
        $regex
}