## Features

* Query VirusTotal Livehunt notifications
* Download matches locally
* Display which YARA rule matched
* Extract the victim site (if applicable)
* Extract the skimmer gate (if possible)
* Store the matched file’s SHA256, matching rule, victim site and gate into a local database

![image](https://user-images.githubusercontent.com/25351665/130902422-0c13d200-bc82-4764-8e54-7fff9db71556.png)

![image](https://user-images.githubusercontent.com/25351665/130902474-a53d28e5-d634-4e87-81b4-bfa2380e9243.png)

![image](https://user-images.githubusercontent.com/25351665/130902508-7c7359b0-8a89-4eac-ae3e-0a73070fc9a2.png)


## Initial setup

The `config.ini` file should be located in the same directory as the main Python script.
It contains your VirusTotal API key and the path to your YARA rules

[VirusTotal]
api_key=[keyhere]

[YARA]
yara_rules=[yourpathtolocalyararules]

The local path to your YARA rules is only needed if you are going to run YARA on files you have downloaded locally (instead of using VT hunting).

## Usage

    ```webskimmers.py -s [OPTION]```

    -h, --help                  Print this help
    -s, --source                Choose a data source (livehunt, local path)

Example: Query your VirusTotal livehunt notifications (requires VT subscription)
 
 ```webskimmers.py -s livehunt```

Example: Check local HTML, JS files saved to your disk

```webskimmers.py -s /home/user/Desktop/files```
