#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Web Skimmer Notification version 1.0
https://github.com/malwareinfosec/webskimmers

Code development started with forking the following repository:
https://github.com/fr0gger/vthunting

Usage:
python web_skimmers.py [options]

Install:
pip install requests slackclient==1.0.7 pymsteams
"""

import requests
import json
import datetime as dt
import re
import smtplib
import getopt
import sys
import sqlite3
import pymsteams
import time
import os
import os.path
import shutil
from requests import *
from datetime import datetime
import yara
import glob
import hashlib
import configparser
#from slackclient import SlackClient

# authorship information
__author__ = "@malwareinfosec"
__team__ = "WebSkimmer hunting tool"
__version__ = "1.0"
__maintainer__ = "@malwareinfosec"
__status__ = "Release 1.0"
__asciiart__ = '''
                                          `.-/+o/`            
                                   `-:+oyhbbbbbbbh`           
                          ``.:/osybbbbbbbbbbbhyso/.           
                  ``.-/+syhbbbbbbbbbbhhyo+:-.                 
             .:+oshbbbbbbbbbbhhys+/-.`        ```-:/          
            -bbbbbbbbhhyso/:-`         ``.:/+syhbbbb-         
            -hhhso+:-.`        ``.-/+osybbbbbbbbbbbby         
             .`        ``.-:/osyhbbbbbbbbbbbbbbbbbbbb:        
                `..:/+syyyhhhhhhhhhhhhhhhhhhhhhhhhhhhs        
              :yyhbbbbo:   
              `hbbbbbo   !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
               +bbbbb/  !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
               `hbbbb/  !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                :bbbb/  !$$$_|_|_$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                 ybbb/  !$$$_|_|_$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                 -ybb/  !$$$ | | $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                  `..`  !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                        !$$ 4111 $$$ 1111 $$$ 1111 $$$ 1111 $$$!
                        !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                        !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                        !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
                         !$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!

        '''
# -----------------------------------------------------------------------
#                               CONFIG INFO
#                       UPDATE WITH YOUR PERSONAL INFO
# -----------------------------------------------------------------------

current_path = os.path.dirname(os.path.realpath(__file__))

number_of_result = ""  # fetch this many notifications per API request. 10 by default, 40 max
max_notifications = None  # fetch this many notifications in total
vturl = 'https://www.virustotal.com/api/v3/intelligence/hunting_notifications'
vtdownload = "https://www.virustotal.com/vtapi/v2/file/download"
data_tmp = current_path + "/data_tmp/"
data_archive = current_path + "/data_archive/"

# Log report
report_log_file = current_path + "/report.log"

# Missing log file location
missing_log_file = current_path + "/missing.log"

# Errors log file location
errors_log_file = current_path + "/errors.log"

# Create an APP on gmail if you are using double authentication https://support.google.com/accounts/answer/185833
smtp_serv = ""
smtp_port = ""
gmail_login = ""
gmail_pass = ""  # pass from APP
gmail_dest = ""

# Slack Bot config
SLACK_BOT_TOKEN = ""
SLACK_EMOJI = ":rooster:"
SLACK_BOT_NAME = ""
SLACK_CHANNEL = ""

# -----------------------------------------------------------------------

# Global Variable
now = dt.datetime.now()
regex = "[A-Fa-f0-9]{64}"  # Detect SHA256
end_message = "End of report"
database_connection = sqlite3.connect('skimmers.sqlite')


# Print help
def usage():
    print("usage: WebSkimmers.py -s [OPTION] -o [OPTION]")
    print('''   
    -h, --help                   Print this help
    -s, --source                 Choose a data source (VT, local)
    -o, --output                 (Optional) Choose an output format (email, slack, tweet)

Example: WebSkimmers.py -s VT
Example: WebSkimmers.py -s /home/user/Desktop/files
    ''')


# Twitter
def send_twitter_notification(report):
    tweet = []
    for line in report.split('\n'):
        if not line.startswith('----'):
            if not (line.startswith('Tags') or line.startswith('Match date')):
                tweet.append(line.rstrip('\n'))
            elif line.startswith('Tags'):
                tweet.append('#WebSkimming')
                tweet = ("\n".join(tweet))
                # Send tweet
                print('Sending tweet: \n')
                print(tweet)
                time.sleep(2)
                # Clear array
                tweet = []
                print('\n')

# Posting to a Slack channel
def send_slack_report(report):
    sc = SlackClient(SLACK_BOT_TOKEN)
    if sc.rtm_connect(with_team_state=False):
        sc.api_call(
            "chat.postMessage",
            icon_emoji=SLACK_EMOJI,
            username=SLACK_BOT_NAME,
            channel=SLACK_CHANNEL,
            text=report
        )
        print("[*] Report has been sent to your Slack channel!")

    else:
        print("[!] Connection failed! Exception traceback printed above.")
        sys.exit()

# Send email report
def send_email_report(report):
    from_email = gmail_login
    to_email = [gmail_dest]  # ['me@gmail.com', 'bill@gmail.com']
    subject = "Virus Total Hunting Report - " + str(now)
    text = report
    message = 'Subject: {}\n\n{}'.format(subject, text)

    try:
        server = smtplib.SMTP_SSL(smtp_serv, smtp_port)
        server.ehlo()
        server.login(from_email, gmail_pass)
        # Send the mail

        server.sendmail(from_email, to_email, message)
        server.quit()
        print("[*] Report have been sent to your email!")
    except smtplib.SMTPException as e:
        print("[!] SMTP error: " + str(e))
        sys.exit()

def initialize_skimmers_database():
    skimmers_sql = """
    CREATE TABLE IF NOT EXISTS skimmers_db (
    sha256 text constraint skimmers_db_pk primary key,
    victim_site text,
    skimmer_gate text,
    rule_name text,
    notification_date int
    );"""
    try:
        database_connection.execute(skimmers_sql)
    except Exception as e:
        print("[!] Error with creating the table in the SQLite3 database: " + str(e))
        sys.exit()
    finally:
        database_connection.commit()

def sha256_was_seen_before(sha256):
    return bool(database_connection.execute(
        'SELECT EXISTS ( SELECT sha256 FROM skimmers_db WHERE sha256 = ?)', [str(sha256)]).fetchone()[0])
        
def victim_site_was_seen_before(victim_site):
    return bool(database_connection.execute(
        'SELECT EXISTS ( SELECT victim_site FROM skimmers_db WHERE victim_site = ?)', [str(victim_site)]).fetchone()[0])
        
def skimmer_gate_was_seen_before(skimmer_gate):
    return bool(database_connection.execute(
        'SELECT EXISTS ( SELECT skimmer_gate FROM skimmers_db WHERE skimmer_gate = ?)', [str(skimmer_gate)]).fetchone()[0])

def update_skimmers_db(sha256, victim_site, skimmer_gate, rule_name, notification_date):
    if not sha256_was_seen_before(sha256):
        try:
            database_connection.execute('INSERT INTO skimmers_db (sha256, victim_site, skimmer_gate, rule_name, notification_date) values (?, ?, ?, ?, ?)', [str(sha256), str(victim_site), str(skimmer_gate), str(rule_name), int(notification_date)])
        except Exception as e:
            print("[!] Error updating the SQLite3 database: " + str(e))
            sys.exit()
        finally:
            database_connection.commit()

# Connect to VT
def api_request(VTAPI):
    print('Checking with VirusTotal API for new notifications, please wait...')
    fetch_more_notifications = True
    limit = 10
    notifications = []
    new_entry = False
    victim_site_found_count = 0
    skimmer_gate_found_count = 0
    victim_site_missed_count = 0
    skimmer_gate_missed_count = 0

    if number_of_result:
        limit = int(number_of_result)
    if max_notifications and max_notifications < limit:
        limit = max_notifications

    params = {
        'limit': limit,
        'filter': 'Magecart'
    }

    headers = {"x-apikey": VTAPI}

    while fetch_more_notifications:
        response = requests.get(vturl, params=params, headers=headers)
        result = json.loads(response.text)

        for json_row in result['data']:
            notifications.append(json_row)

        # Response has cursor, more notifications can be fetched
        if 'cursor' in result['meta'].keys():
            params.update({'cursor': result['meta']['cursor']})

            if max_notifications:
                # reached limit, stop fetching more notifications
                if len(notifications) == max_notifications:
                    fetch_more_notifications = False
                # limit amount of notifications to fetch on next iteration, to reach max
                elif len(notifications) + limit > max_notifications:
                    params.update({'limit': max_notifications - len(notifications)})
        else:
            fetch_more_notifications = False

    # Start report
    report = ["-------------------------------------------------------------------------------------"]

    for json_row in notifications:
        rule_name = json_row["attributes"]["rule_name"]
        date = json_row["attributes"]["date"]
        tags = json_row["attributes"]["tags"]
        snippet = json_row["attributes"]["snippet"]
        sha256 = re.search(regex, str(tags)).group()
        tags.remove(sha256)

        # Only continue if hash was not seen before
        if not sha256_was_seen_before(sha256):
            # Call function to download file from VT
            download_file_vt(VTAPI, sha256, data_tmp)
            # Call function to search file for a victim
            victim_site = find_victim(sha256, data_tmp)
            # Check if victim_site already exists
            if victim_site is not None:
                victim_exists = victim_site_was_seen_before(victim_site)
            # Call function to search file for a gate
            skimmer_gate = find_gate(sha256, data_tmp)
            # Check if skimmer_gate already exists
            if skimmer_gate is not None:
                gate_exists = skimmer_gate_was_seen_before(skimmer_gate)
            # Update database
            update_skimmers_db(sha256, victim_site, skimmer_gate, rule_name, date)
            
            # Only continue if we have either a new victim site or skimmer gate
            if (victim_site is not None and not victim_exists) or (skimmer_gate is not None and not gate_exists):
                new_entry = True
                report.append("Rule name: " + rule_name)
                report.append("Match date: " + datetime.utcfromtimestamp(date).strftime('%m/%d/%Y'))
                report.append("SHA256: " + str(sha256))
                if (victim_site is not None and not victim_exists):
                    report.append("Victim site: " + victim_site.replace(".", "[.]"))
                    victim_site_found_count += 1
                if (skimmer_gate is not None and not gate_exists):
                    report.append("Skimmer gate: " + skimmer_gate.replace(".", "[.]"))
                    skimmer_gate_found_count += 1
                report.append("Tags: " + str([str(tags) for tags in tags]).replace("'", ""))
                report.append("Snippet: " + snippet)
                report.append("-------------------------------------------------------------------------------------")
            else:
                with open(missing_log_file, 'a') as f:
                    if victim_site is None:
                        f.write(sha256 + " no victim site found\n")
                        victim_site_missed_count += 1
                    if skimmer_gate is None:
                        f.write(sha256 + " no skimmer gate found\n")
                        skimmer_gate_missed_count += 1

        # Move file
        if os.path.isfile(data_tmp + sha256):
            shutil.move(data_tmp + sha256, data_archive + sha256)

    if new_entry:
        report.append("\nSTATS:")
        report.append("Victim sites found: " + str(victim_site_found_count))
        report.append("Victim sites missed: " + str(victim_site_missed_count))
        report.append("Skimmer gates found: " + str(skimmer_gate_found_count))
        report.append("Skimmer gates missed: " + str(skimmer_gate_missed_count) + "\n")
    
    if not new_entry:
        print("No new entry!")    
    
    #report.append(end_message)
    report = ("\n".join(report))
    
    return report, notifications

table = []

def mycallback(data):
  #print(data)
  table.append(data)
  return yara.CALLBACK_CONTINUE


# Local folder
def local_folder(yara_rules,data_dir):
    # Scan with YARA rules
    rules = {}
    path = yara_rules + "/"
    for rule in glob.glob(path + '*.yar'):
        rules[rule] = rule

    rules = yara.compile(filepaths=rules)

    # Start report
    report = ["-------------------------------------------------------------------------------------"]

    for filename in os.listdir(data_dir):
        matches = rules.match(data_dir + filename, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES)
        with open(data_dir + filename,"rb") as f:
            bytes = f.read() # read entire file as bytes
            sha256 = hashlib.sha256(bytes).hexdigest()
        if matches:
            # Only continue if hash was not seen before
            if not sha256_was_seen_before(sha256):
                # Update match date
                day = now.strftime("%d")
                month = now.strftime("%m")
                year = now.strftime("%Y")
                date = month + "/" + day + "/" + year
                # Call function to search file for a victim
                victim_site = find_victim(filename, data_dir + "/")
                # Check if victim_site already exists
                if victim_site is not None:
                    victim_exists = victim_site_was_seen_before(victim_site)
                # Call function to search file for a gate
                skimmer_gate = find_gate(filename, data_dir + "/")
                # Check if skimmer_gate already exists
                if skimmer_gate is not None:
                    gate_exists = skimmer_gate_was_seen_before(skimmer_gate)
                # Update database
                update_skimmers_db(sha256, victim_site, skimmer_gate, table[-1]['rule'], int(time.time()))
                # Only continue if we have either a new victim site or skimmer gate
                if (victim_site is not None and not victim_exists) or (skimmer_gate is not None and not gate_exists):
                    report.append("Rule name: " + table[-1]['rule'])
                    report.append("Match date: " + date)
                    report.append("SHA256: " + str(sha256))
                    if (victim_site is not None and not victim_exists):
                        report.append("Victim site: " + victim_site.replace(".", "[.]"))
                    if (skimmer_gate is not None and not gate_exists):
                        report.append("Skimmer gate: " + skimmer_gate.replace(".", "[.]"))
                    report.append("Tags: " + ", ".join(table[-1]['tags']))
                    report.append(str(list(table[-1]['strings'])))
                    report.append("-------------------------------------------------------------------------------------")
            # Move file
            if os.path.isfile(data_dir + sha256):
                shutil.move(data_dir + sha256, data_archive + sha256)

    report = ("\n".join(report))
    return report

# Download file from VT
def download_file_vt(VTAPI, sha256, data_tmp):
        r = requests.get(vtdownload, params={"apikey": VTAPI, "hash": sha256})
        with open(data_tmp + sha256, "wb") as f:
            f.write(r.content)

# Find victim site from file        
def find_victim(sha256, data_tmp):
    victim_site = None
    try:
        with open(data_tmp + sha256, 'r', errors='replace') as f:
            for line in f.readlines():
                if ('link rel="shortcut icon' in line) and (line.find('http') != -1):
                    victim_site = re.sub('/.*', '',re.sub('^.*shortcut icon.*?href="https?://(www.)?', '', line)).strip('\n')
                    return victim_site
                elif ('var BLANK_URL = ' in line) and (line.find('http') != -1):
                    victim_site = re.sub('/.*', '', re.sub('^.*?(\'|")https?://(www.)?', '', line)).strip('\n')
                    return victim_site
                elif ('<base href="http' in line):
                    victim_site = re.sub('/.*', '', re.sub('^.*?(\'|")https?://(www.)?', '', line)).strip('\n')
                    return victim_site
                elif ('<link rel="pingback"' in line) and (line.find('http') != -1):
                    victim_site = re.sub('/.*', '', re.sub('^.*?(\'|")https?://(www.)?', '', line)).strip('\n')
                    return victim_site
                elif ('"baseUrl": "' in line) and (line.find('http') != -1):
                    victim_site = re.sub('/.*', '', re.sub('^.*?(\'|")https?://(www.)?', '', line)).strip('\n')
                    return victim_site
    except Exception as e:
        with open(missing_log_file, 'a') as f:
            f.write("[!] Error with finding victim_site with: " + sha256 + " : " + str(e))

# Find skimmer gate from file
def find_gate(sha256, data_tmp):
    skimmer_gate = None
    try:
        with open(data_tmp + sha256, 'r', errors='replace') as f:
            for line in f.readlines():
                if 'Gate: "' in line:
                    skimmer_gate = re.sub('",', '', re.sub('^.*?Gate:\s"https?://(www.)?', '', line)).strip('\n')
                    if skimmer_gate is not None:
                        return skimmer_gate
                if 'x68' in line:
                    hex_tmp = re.search('\\\\x68\\\\x74\\\\x74\\\\x70\\\\x73\\\\x3A\\\\x2F\\\\x2F(.*?)\\\\x2F', line, re.IGNORECASE)
                    if hex_tmp is not None:    
                        hex_tmp = hex_tmp.group(1)
                        skimmer_gate = hex_text(hex_tmp)
                        return skimmer_gate
                #if 'String.fromCharCode' in line:
                #    char_code = re.search('fromCharCode\((.*?)\)', line).group(1)
                #    skimmer_gate = ""
                #    for char in char_code.split(","):
                #        skimmer_gate = skimmer_gate + (chr(int(char)))
                #    return skimmer_gate
    except Exception as e:
        with open(missing_log_file, 'a') as f:
            f.write("[!] Error with finding skimmer_gate with: " + sha256 + " : " + str(e))

# Convert hex to text
def hex_text(hex_tmp):
    hex_tmp = re.sub('\\\\x', '', hex_tmp)
    txt_tmp = bytes.fromhex(hex_tmp).decode('utf-8')
    return txt_tmp

def main(argv):
    print(__asciiart__)
    print("\t         " + __team__ + " | " + __author__ + "\n")

    # Read config file
    try:
        config = configparser.ConfigParser()
        config.read("config.ini")
        VTAPI = config.get("VirusTotal", "api_key")
        yara_rules= config.get("YARA", "yara_rules")
    except Exception as e:
        print("[!] Unable to read the config.ini file: {}".format(str(e)))

    try:
      opts, args = getopt.getopt(argv,"hs:o:",["source=","output="])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-s", "--source"):
            if arg == "VT":
                # VirusTotal as source
                initialize_skimmers_database()
                try:
                    report, result_json = api_request(VTAPI)
                    if len(sys.argv) > 3:
                        output = (sys.argv[4])
                    else:
                        output = "console"
                except(ConnectionError, ConnectTimeout, KeyError) as e:
                    print("[!] Error with the VT API: " + str(e))
                    sys.exit()
                database_connection.close()
            elif os.path.isdir(arg):
                # Local folder as source
                initialize_skimmers_database()
                try:
                    data_dir = (arg) + "/"
                    report = local_folder(yara_rules, data_dir)
                    if len(sys.argv) > 3:
                        output = (sys.argv[4])
                    else:
                        output = "console"
                except Exception as e:
                    print("[!] Error with local folder: " + str(e))
                    sys.exit()
                database_connection.close()
            else:
                usage()
                sys.exit()

    if output == "console":
        print(report)


if __name__ == '__main__':
    main(sys.argv[1:])
