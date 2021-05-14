rule Image_WebSkimmer : Magecart WebSkimmer Image
{
    meta:
        author = "JS"
        description = "Image WebSkimmer"
        reference = "https://blog.sucuri.net/2020/07/skimmers-in-images-github-repos.html"
        date = "2021-04-09"
    
    strings:
        $regex = /let\sx\s=\sawait\sx92\.text\(\)/
    
    condition:
        $regex
}