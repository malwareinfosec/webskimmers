rule obj_31337_WebSkimmer : Magecart WebSkimmer obj_31337
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (obj_31337)"
		source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://lukeleal.com/research/posts/magento2-payprocess-obj_31337-skimmer/"
        date = "2022-02-04"
        
    strings:
        $string = "obj_31337['dbg_addr']"
		$string2 = "function called_outside_ready"
    
    condition:
        $string or $string2
}