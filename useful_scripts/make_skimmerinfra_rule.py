#!/usr/bin/env python

import sys
from datetime import datetime

if len(sys.argv) <= 1:
    print('Usage: make_yara_rule.py -i input')
    exit(1)
	
yara_rule = []
yara_rule.append('import "vt"')
yara_rule.append('rule Infra_WebSkimmer : Magecart WebSkimmer Infra')
yara_rule.append('{')
yara_rule.append('    meta:')
yara_rule.append('        author = "Jérôme Segura"')
yara_rule.append('        description = "Skimmer rule based on skimming infrastructure"')
yara_rule.append('        description = "Skimmer rule based on skimming infrastructure"')
yara_rule.append('        reference = "https://github.com/malwareinfosec/webskimmers"')
yara_rule.append('        date = ' + '"' + datetime.today().strftime('%Y-%m-%d') + '"')

yara_rule.append('    strings:')

with open(sys.argv[2], "r") as f:
    for line in f.readlines():
        yara_rule.append("        " + "$" + " = " + "\"//" + line.strip('\n') + "/" + "\"")

yara_rule.append('')
yara_rule.append('        ' + 'condition:')
yara_rule.append('        ' + 'any of them and (vt.metadata.file_type == vt.FileType.SCRIPT or vt.metadata.file_type == vt.FileType.HTML) and vt.metadata.new_file')
yara_rule.append('}')


yara_rule = ("\n".join(yara_rule))


with open('Infra_WebSkimmer.yar', 'a') as f:
    f.write(yara_rule)
