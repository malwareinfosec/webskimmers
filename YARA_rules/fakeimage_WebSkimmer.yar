rule fakeimage_WebSkimmer : Magecart WebSkimmer fakeimage
{
    meta:
        author = "Jérôme Segura"
        description = "Magecart (fakeimage)"
        source = "https://github.com/malwareinfosec/webskimmers/"
        reference = ""
        date = "2022-02-10"

	strings:
	    $string = { 29 3B } // Look for );
		$string2 = { 7D 3B } // Look for };
		$string3 = { 7D 7D } // Look for }}
    
    condition:
        (uint16be(0x00) == 0xFFD8 or uint16be(0x00) == 0x8950) and ($string in (filesize-2..filesize)
		or $string2 in (filesize-2..filesize) or $string3 in (filesize-2..filesize)) and filesize < 500KB
}

