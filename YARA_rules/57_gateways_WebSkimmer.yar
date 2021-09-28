rule 57_gateways_WebSkimmer : Magecart WebSkimmer 57_gateways
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (57_gateways)"
		source = "https://github.com/malwareinfosec/webskimmers/"
        reference = "https://sansec.io/research/polymorphic-skimmer-57-payment-gateways"
        date = "2021-09-25"
        
    strings:
        $regex = /'1f1612164c041c515b1509011f0d03',\s'13101206530e1946'/
    
    condition:
        $regex
}