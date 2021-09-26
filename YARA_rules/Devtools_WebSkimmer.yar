rule Devtools_WebSkimmer : Magecart WebSkimmer Devtools
{
    meta:
        author = "@malwareinfosec"
        description = "Magecart (Devtools)"
        reference = ""
        date = "2021-09-25"
        
    strings:
        $regex = /(devtools.isOpen)|(devtools.open)/
		$regex2 = /(is_valid_luhn)|(img.src\s=\swindow.atob)/
    
    condition:
        $regex and $regex2
}