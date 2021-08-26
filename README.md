

The `config.ini` file should be located in the same directory as the main Python script.
It contains your VirusTotal API key and the path to your YARA rules

[VirusTotal]
api_key=[keyhere]

[YARA]
yara_rules=[yourpathtolocalyararules]

The local path to your YARA rules is only needed if you are going to run YARA on files you have downloaded locally (instead of using VT hunting).

##
Usage:
    ```webskimmers.py -s [OPTION]```

    -h, --help                  Print this help
    -s, --source                Choose a data source (livehunt, local path)

Example: Query your VirusTotal livehunt notifications (requires VT subscription)
 
 ```webskimmers.py -s livehunt```

Example: Check local HTML, JS files saved to your disk

```webskimmers.py -s /home/user/Desktop/files```
