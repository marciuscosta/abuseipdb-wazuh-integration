#!/var/ossec/framework/python/bin/python3
#
# This script get informations about a IP querying on AbuseIPDB and make cache with this information to skip a new query online, saving queries diary limit.
#
# Based on the article: https://wazuh.com/blog/detecting-known-bad-actors-with-wazuh-and-abuseipdb/
#
# by Marcius Costa - https://marcius.pro
# 02/2024

import sys
import json
import time
import os
import fcntl
import re
import random
import datetime
import subprocess
import traceback

# Verifing if 'requests' module is installed
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Execute to install: pip3 install requests")
    sys.exit(1)

# Verifing if 'sqlite3' module is installed
try:
    import sqlite3
except Exception as e:
    print("No module 'sqlite3' found. Execute to install: pip3 install sqlite3")
    sys.exit(1)

# Verifing if 'ipaddress' module is installed
try:
    import ipaddress
except Exception as e:
    print("No module 'ipaddress' found. Execute to install: pip3 install ipaddress")
    sys.exit(1)

#
# Global variables definition
#
# Directory of Wazuh
ossecdir = "/var/ossec/"
# Fields names where have a IP address from alert content
ip_fields = ['srcip', 'dstip', 'IP', 'LocalIp', 'ip_address', 'ip.address', 'ipaddr', 'source_address', 'destination_address', 'dst_ip', 'dstcip', 'src_ip', 'host_ip', 'ip', 'mapped_src_ip', 'mapped_dst_ip', 'remote_peer', 'client_dyn_ip', 'remote-peer', 'locip', 'mariadb.ip', 'nat_srcip', 'nat_dstip', 'remip', 'srcip2', 'nat_source_ip', 'nat_destination_ip', 'tran_dst_ip', 'tran_src_ip', 'transip', 'tunnelip', 'src', 'dst', 'destinationIp', 'sourceIp', 'ipAddress', 'origin', 'peer_gateway', 'fw']
# Maximum age in days on AbuseIPDB as consider
maxAgeInDays = 90
# Database file with last results of queries on AbuseIPDB. This file will be read before a consult on AbuseIPDB, to skip "requeries" of a same IP recently queried
abuseipdb_local_cache_file = ossecdir + "var/db/abuseIPDB_local_cache.db"
# Format date and time for this logging - If you change it, fix the decoder
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Log file that will be read by Wazuh decoders
log_file = ossecdir + "logs/integrations.log"
# Variable will store the full content of alert received
alert_content = None
# Define if blacklist will be used (True) or not (False)
blacklist_enabled = True
# Destination directory where blacklist will be saved on download from AbuseIPDB
blacklist_file = ossecdir + "etc/lists/abuseipdb_blacklist"
# Minimum level of confidence to download blacklist from AbuseIPDB
confidenceMinimum = 75
# Expiration time of an IP stored in local cache database. Upon expiration, a new query will be made to AbuseIPDB and an update will be executed on this database
ip_expiration_time = 86400  # Set it with seconds. Example for 24 hours = 86400
# URL of AbuseIPDB to check an IP
api_abuseipdb_url_check = "https://api.abuseipdb.com/api/v2/check"
# URL of AbuseIPDB to download blacklist
api_abuseipdb_url_blacklist = "https://api.abuseipdb.com/api/v2/blacklist"

def logging(to_log):
    with open(log_file, 'a') as log:
        # Set a log format to read by Wazuh decoders
        log.write("AbuseIPDB_integration|" + now + "|" + str(to_log) + '\n')
        log.close()

def get_alert_content():
    with open(sys.argv[1], 'r') as json_alert:
        global alert_content
        alert_content = json_alert.read()
        json_alert.close()

# Find recursively fields, start at 'data' JSON key, with any name in "ip_fields" variable and return all IPs found
def find_ip_in_fields(json_alert, ip_fields, current_path=""):
    fields_found = []
    for key, value in json_alert.items():
        path = f"{current_path}.{key}" if current_path else key
        if isinstance(value, dict):
            fields_found.extend(find_ip_in_fields(value, ip_fields, path))
        else:
            if key in ip_fields:
                fields_found.append(value)

    return fields_found

# Verify if IPs found in find_ip_fields are public
def extract_public_ip():
    global ip_fields
    global alert_content
    if alert_content:
        # Load alert in JSON format
        json_alert = json.loads(alert_content)
        public_ip_found = []
        # Return all IPs found in alert content from known fields in ip_fields variable.
        ips_found = find_ip_in_fields(json_alert["data"], ip_fields)
        for ip in ips_found:
            try:
                ip_type = ipaddress.ip_address(ip)
                #Save all public IPs found in public_ip_found variable
                if isinstance(ip_type, ipaddress.IPv4Address) or isinstance(ip_type, ipaddress.IPv6Address):
                    if not (ip_type.is_private or ip_type.is_loopback or ip_type.is_multicast):
                        public_ip_found.append(ip)
            except ValueError:
                pass

        # Return if IP is public
        if not public_ip_found == []:
            return list(set(public_ip_found))
        else:
            return "no_public_ip_found"
    else:
        logging("Error: No JSON alert was received.")
        exit(1)

def query_api(ip):
    if (return_set_apikey := manage_apikeys("set_apikey", 0)) is not None:
        # If not stored any API keys in local cache database, stop this script with error
        if return_set_apikey == "no_apikey_found":
            logging("ERROR: No API key found in local cache database. Add a valid API key using this command: " + sys.argv[0] + " apikey add YOUR_VALID_API_KEY_HERE")
            print("ERROR: No API key found in local cache database. Add a valid API key using this command: " + sys.argv[0] + " apikey add YOUR_VALID_API_KEY_HERE")
            return "no_apikey_found"
        apiKey = return_set_apikey
    else:
        logging("ERROR: All API key(s) stored in local cache database has been exceeded daily limit or invalid. List all API keys stored with this command: " + sys.argv[0] + " apikey list")
        return "all_apikeys_unusable"
    params = {'maxAgeInDays': maxAgeInDays, 'ipAddress': ip,}
    headers = {
    "Accept-Encoding": "gzip, deflate",
    'Accept': 'application/json',
    "Key": apiKey
    }

    # Will query about an IP in the AbuseIPDB API
    response = requests.get(api_abuseipdb_url_check,params=params, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        abuseipdb_data = json_response["data"]
        return str(abuseipdb_data)
    # if daily limit utilization has been exceeded, will be update the API key to not use before next midnight in UTC.
    elif response.status_code == 429:
        manage_apikeys("update_daily_limit", apiKey)
        return "daily_limit_exceeded"
    # If the API key selected to use is a invalid, mark then as invalid on local cache database.
    elif response.status_code == 401:
        manage_apikeys("mark_apikey_as_invalid", apiKey)
        logging("The " + apiKey + " API key is invalid. Check it in your account on AbuseIPDB or fix in local cache database with this command: " + sys.argv[0] + " apikey list") 
        return "invalid_apikey"
    else:
        logging("ERROR: Can't get information about " + ip + " in AbuseIPDB. Original message: " + str(response))
        exit(1)

def local_cache_connection():
    global abuseipdb_local_cache_file
    # Verifing if cache file exists. If not, create it
    if not os.path.exists(abuseipdb_local_cache_file):
        with open(abuseipdb_local_cache_file, 'w'):
            os.chmod(abuseipdb_local_cache_file, 0o660)
            chown = ['chown', 'root:wazuh', abuseipdb_local_cache_file]
            subprocess.run(chown)
            logging("Cache file does not exit. Creating it in " + abuseipdb_local_cache_file)

    # Make connection with cache file SQLite
    connection = sqlite3.connect(abuseipdb_local_cache_file)
    cursor = connection.cursor()
    # Creating a table to use as a cache of informations about IPs queried in AbuseIPDB
    cursor.execute('''CREATE TABLE IF NOT EXISTS ip (ip TEXT PRIMARY KEY, last_query INTEGER, abuseipdb_data TEXT)''')

    # Creating a table to store API keys of AbuseIPDB
    cursor.execute('''CREATE TABLE IF NOT EXISTS api_key (apikey TEXT PRIMARY KEY, usable_after INTEGER)''')

    return connection, cursor

def local_cache():
    global ip_expiration_time
    timestamp_now = int(time.time())
    connection, cursor = local_cache_connection()
    # Get all public IPs found in alert
    get_public_ip = extract_public_ip()

    # If no public IP is found, exit the script
    if get_public_ip == "no_public_ip_found":
        exit(0)

    for ip in get_public_ip:
        cursor.execute("SELECT * FROM ip WHERE ip = ?", (ip,))
        select_result = cursor.fetchall()
        # If IP does not exist in local cache...
        if not select_result:
            # ... attempt to find in blacklist, if it was downloaded and enabled
            if blacklist_enabled == True:
                # If the blacklist has not yet been downloaded, it will be downloaded
                if not os.path.exists(blacklist_file):
                    download_blacklist(blacklist_file)
                try:
                    full_data, find_ip_blacklist_result = find_ip_blacklist(ip)
                except:
                    find_ip_blacklist_result = None
            else:
                find_ip_blacklist_result = "blacklist_disabled"

            # If IP was found in blacklist, return infos about it
            if find_ip_blacklist_result == "ip_found_in_blacklist":
                format_log_to_decoder(full_data, find_ip_blacklist_result)

            # If IP does not found in blacklist (or it was disabled), insert informations about this IP in local cache database
            else:
                abuseipdb_data = query_api(ip)
                while abuseipdb_data == "daily_limit_exceeded" or abuseipdb_data == "invalid_apikey":
                    abuseipdb_data = query_api(ip)
                if abuseipdb_data == "all_apikeys_unusable":
                    logging("ERROR: Can't get informations about IP " + ip + " because all API key(s) stored in local cache database has been exceeded daily limit or invalid.")
                    exit(0)
                if abuseipdb_data == "no_apikey_found":
                    logging("ERROR: Can't get informations about IP " + ip + " because no API keys was found in local cache database.")
                    exit(0)
                logging("Creating informations about " + ip + " in local cache file")
                full_data = str(abuseipdb_data)
                cursor.execute("INSERT INTO ip (ip, last_query, abuseipdb_data) VALUES (?, ?, ?)", (ip, timestamp_now, full_data))
                connection.commit()
                format_log_to_decoder(abuseipdb_data, "ip_found_in_local_cache_db")

        # If IP was found on local cache database, execute it
        else:
            # Checks whether the information stored in local cache database about this IP has expired according to the ip_expiration_time variable defined at the top of this script
            ip_last_queried = select_result[0][1]
            # If informations about IP was expired in local cache database, will update it
            if ip_last_queried + ip_expiration_time < timestamp_now:
                logging("Informations about IP " + ip + " has expired and will attempt to be updated. Last query about it: " + str(datetime.datetime.fromtimestamp(ip_last_queried)))
                abuseipdb_data = query_api(ip)
                # Will look for a valid API key in local cache database
                while abuseipdb_data == "daily_limit_exceeded" or abuseipdb_data == "invalid_apikey":
                    # Will search again if the API key has exceeded the daily limit or is invalid
                    abuseipdb_data = query_api(ip)
                # If all API keys are unusable because are invalid or has exceeded daily limit, go ahead and show last informations about IP in local cache
                if abuseipdb_data == "all_apikeys_unusable" or abuseipdb_data == "no_apikey_found":
                    format_log_to_decoder(select_result, "ip_found_in_local_cache_db")
                else:
                    try:
                        full_data = str(abuseipdb_data)
                        cursor.execute("UPDATE ip SET last_query = ?, abuseipdb_data = ? WHERE ip = ?", (timestamp_now, full_data, ip,))
                        connection.commit()
                        logging("Successfully updated informations about IP " + ip + " on local cache database.")
                        format_log_to_decoder(full_data, "ip_found_in_local_cache_db")
                    except:
                        logging("ERROR: Can't update informations about IP " + ip + " on local cache database. Message: " + str(sys.exc_info()))
            else:
                format_log_to_decoder(select_result, "ip_found_in_local_cache_db")
    connection.close()

def manage_apikeys(apikey_action, apikey):
    # Add a API key in local cache database
    if apikey_action == "add":
        # Verify if API key informed have a valid length.
        if len(apikey) != 80:
            print("Your API key is invalid. A valid API key have 80 characters. Your API key have " + str(len(apikey)) + " characters.")
            exit(1)

        # If API key informed is valid, make connection with local cache database
        connection, cursor = local_cache_connection()
        # Insert API key in local cache database, if it doesn't already exist
        try:
            now = int(time.time())
            cursor.execute("INSERT INTO api_key (apikey, usable_after) VALUES (?, ?)", (apikey, now,))
            connection.commit()
            print("API key " + str(apikey) + " added with success.")
        except:
            cursor.execute("SELECT * FROM api_key WHERE apikey = ?", (apikey,))
            apikeys_found = cursor.fetchall()
            # If the error is because this API key already exists in local cache database, print this error message
            if len(apikeys_found) > 0:
                print("This API key already exist on local cache database.")
                print("Use this command to list all API keys stored: " + sys.argv[0] + " apikey list")
                exit(1)
            # If the error is due to another cause, print this error message below
            print("Error on add the API key " + apikey + ".")
            print(sys.exc_info())
            exit(1)
        finally:
            connection.close()

    # Remove a API key in local cache database
    elif apikey_action == "remove":
        connection, cursor = local_cache_connection()
        try:
            cursor.execute("DELETE FROM api_key WHERE apikey = ?", (apikey,))
            connection.commit()
            print("API key " + apikey + " removed with success.")
        except:
            print("Error on remove the API key " + apikey + ".")
            print(sys.exc_info())
            exit(1)
        finally:
            connection.close()

    # Listing all API keys stored in local cache database
    elif apikey_action == "list":
        connection, cursor = local_cache_connection()
        try:
            cursor.execute("SELECT * FROM api_key")
            all_apikeys_saved = cursor.fetchall()
            if len(all_apikeys_saved) == 0:
                print("----------------------------------------------------------------------------------------------------------------------------------" + '\n')
                print(" ERROR: No one API key stored in local cache database. Add a API key using: " + sys.argv[0] + " apikey add YOUR_API_KEY_HERE" + '\n')
                print("----------------------------------------------------------------------------------------------------------------------------------" + '\n')
            else:
                for apikey_saved in all_apikeys_saved:
                    if apikey_saved[1] == 99999999999:
                        readable_usable_after = "INVALID"
                    else:
                        readable_usable_after = str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(apikey_saved[1])))

                    print("----------------------------------------------------------------------------------------------------------------------------------" + '\n')
                    print("API Key: " + str(apikey_saved[0]) + '\t' + "Usable after: " + readable_usable_after + '\n')
                print("----------------------------------------------------------------------------------------------------------------------------------" + '\n')
        except:
            print("ERROR: Can't trying get all API keys stored in local cache database.")
            print(sys.exc_info())
            exit(1)
        finally:
            connection.close()

    # Get a valid API key stored in local cache file.
    # Is consider a valid API key where the timestamp in "usable_after" column is older than timestamp_now variable value
    elif apikey_action == "set_apikey":
        all_valid_apikeys_found = []
        all_apikeys_found = []
        connection, cursor = local_cache_connection()
        timestamp_now = int(time.time())
        # Query only API keys that are usable
        cursor.execute("SELECT * FROM api_key WHERE usable_after < ?", (timestamp_now,))
        all_valid_apikeys_found = cursor.fetchall()
        # Query all API keys stored in local cache database
        cursor.execute("SELECT * FROM api_key")
        all_apikeys_found = cursor.fetchall()
        cursor.close()
        connection.close()

        # Verify if any API key are usable (non invalid or has daily limit exceeded)
        if len(all_valid_apikeys_found) > 0:
            apiKey = str(all_valid_apikeys_found[0][0])
            return apiKey
        else:
            # If exist one or more API keys stored in local cache database, but all are not usable, return None
            if len(all_apikeys_found) > 0:
                return None
                exit(1)
            # If no API key are stored in local cache database, return "no_apikey_found"
            else:
                return "no_apikey_found"
                exit(1)

    # Update API key daily limit, change the timestamp in "usable_after" to now timestamp.
    # Will prevent use of this API key until next midnight (UTC), at which point it will be allowed again.
    elif apikey_action == "update_daily_limit":
        connection, cursor = local_cache_connection()
        try:
            # Calculate the second minute of the next day minus local timezone, to specific when the API key will be usable
            # The second minute after the next midnight was used to avoid failure if local time is different from the remote server
            # AbuseIPDB renew daily limit of a API key daily at midnight in UTC
            now = datetime.datetime.now()
            local_tzone = now.astimezone().tzinfo
            local_tzone_secs_since_utc = local_tzone.utcoffset(None).total_seconds() / 60 * 60
            today_utc = datetime.datetime.utcnow()
            tomorrow = datetime.datetime.combine(today_utc + datetime.timedelta(days=1), datetime.time(0, 2, 0))
            tomorrow_timestamp = tomorrow.timestamp()
            usable_after = tomorrow_timestamp + int(local_tzone_secs_since_utc)
            # Updating when the API key can be used
            cursor.execute("UPDATE api_key SET usable_after = ? WHERE apikey = ?", (usable_after, apikey,))
            connection.commit()
        except:
            logging("ERROR: Can't update daily limit information about " + apikey + " API key. Message: " + str(sys.exc_info()))
            exit(1)
        finally:
            connection.close()

    elif apikey_action == "mark_apikey_as_invalid":
        connection, cursor = local_cache_connection()
        try:
            cursor.execute("UPDATE api_key SET usable_after = 99999999999 WHERE apikey = ?", (apikey,))
            connection.commit()
            logging("The " + apikey + " was marked as invalid.")
        except:
            logging("Error on setting a API key as invalid. Message: " + str(sys.exc_info()))
            exit(1)
        finally:
            connection.close()

    else:
        print("Error using apikey command. " + '\n' +
        "Use \"add API_KEY\" to add a API key. Example: " + sys.argv[0] + " apikey add YOUR_API_KEY_HERE" + '\n' +
        "Or use \"remove API_KEY\" to remove a specific API key. Example: "+ sys.argv[0] + " apikey remove YOUR_API_KEY_HERE" + '\n' +
        "Or use \"list\" to view all API keys stored in local cache. Example: " + sys.argv[0] + " apikey list")

def download_blacklist(blacklist_file):
    if (return_set_apikey := manage_apikeys("set_apikey", 0)) is not None:
        # If not stored any API keys in local cache database, stop this script with error
        if return_set_apikey == "no_apikey_found":
            logging("ERROR[Blacklist]: No API key found in local cache database. Add a valid API key using this command: " + sys.argv[0] + " apikey add YOUR_VALID_API_KEY_HERE")
            print("ERROR[Blacklist]: No API key found in local cache database. Add a valid API key using this command: " + sys.argv[0] + " apikey add YOUR_VALID_API_KEY_HERE")
            exit(1)
        apiKey = return_set_apikey
    else:
        logging("ERROR[Blacklist]: All API key(s) stored in local cache database has been exceeded daily limit or invalid. List all API keys stored with this command: " + sys.argv[0] + " apikey list")
        print("ERROR[Blacklist]: All API key(s) stored in local cache database has been exceeded daily limit or invalid. List all API keys stored with this command: " + sys.argv[0] + " apikey list")
        return "all_apikeys_unusable"

    success_download = 1
    while success_download == 1:
        params = {'confidenceMinimum': confidenceMinimum,}
        headers = {
        "Accept-Encoding": "gzip, deflate",
        'Accept': 'application/json',
        "Key": apiKey
        }
        response = requests.get(api_abuseipdb_url_blacklist,params=params, headers=headers)
        if response.status_code == 200:
            with open(blacklist_file, 'wb') as blacklist:
                blacklist.write(response.content)
                blacklist.close()
                print("Blacklist successfully downloaded and saved to " + blacklist_file)
                logging("Blacklist successfully downloaded and saved to " + blacklist_file)
                success_download = 0
        # If API key has been exceeded daily limit
        elif response.status_code == 429:
            logging("ERROR[Blacklist]: The API key "+ apiKey + " has exceeded daily limit.")
            print("ERROR[Blacklist]: The API key "+ apiKey + " has exceeded daily limit.")
            exit(1)
        # If the API key selected to use is a invalid, mark then as invalid on local cache database.
        elif response.status_code == 401:
            manage_apikeys("mark_apikey_as_invalid", apiKey)
            logging("ERROR[Blacklist]: The " + apiKey + " API key is invalid. Check it in your account on AbuseIPDB or fix in local cache database with this command: " + sys.argv[0] + " apikey list")
            print("ERROR[Blacklist]: The " + apiKey + " API key is invalid. Check it in your account on AbuseIPDB or fix in local cache database with this command: " + sys.argv[0] + " apikey list")
            return "invalid_apikey"
        else:
            print("ERROR[Blacklist]: Can't download blacklist from AbuseIPDB. Erro message from server: " + str(response.content))
            logging("ERROR[Blacklist]: Can't download blacklist from AbuseIPDB. Erro message from server: " + str(response.content))
            exit(1)

def find_ip_blacklist(ip):
    global blacklist_file
    if os.path.exists(blacklist_file):
        with open(blacklist_file, 'r') as blacklist:
            json_data = json.load(blacklist)
            blacklist.close()
        object_full = []
        for object_item in json_data['data']:
            if object_item['ipAddress'] == ip:
                object_full.append(json.dumps(object_item, indent=2))
                return object_full, "ip_found_in_blacklist"
        return "non-data", "ip_not_found_in_blacklist"
    else:
        logging("ERROR: Blacklist not found in " + blacklist_file + ". To download a blacklist, execute: " + sys.argv[0] + " blacklist")

def fix_json_malformed(json_data):
    try:
        json_fixed = re.sub(r': (None|True|False),', r': "\1",', json_data)
        json_fixed = re.sub(': None}', ': "None"}', json_fixed)
        return json_fixed
    except:
        logging("ERROR: Can't fix JSON data. Message " + str(sys.exc_info()))
        exit(1)

def format_log_to_decoder(full_data, from_location):
    # Collect informations about original alert
    alert_json = json.loads(alert_content)
    alert_id = alert_json['id']

    # Collect informations about queried IP on blacklist (is enabled) or local cache database
    if from_location == "ip_found_in_blacklist":
        data_json = json.loads(full_data[0])
        ip = data_json['ipAddress']
        country = data_json['countryCode']
        score = data_json['abuseConfidenceScore']
        lastReported = data_json['lastReportedAt']
        blacklist_file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(blacklist_file))
        from_location = "Blacklist downloaded at " + str(blacklist_file_mtime.strftime("%Y-%m-%d %H:%M:%S"))
        format_data_to_log = "From_location: \"" + from_location  + "\"|IP: \"" + str(ip) + "\"|IP_last_checked: \"" + str(blacklist_file_mtime) + "\"|Country_code: \"" + str(country) + "\"|Abuse_confidence_score: \"" + str(score) + "\"|Last_reported_at: \"" + str(lastReported) + "\""

    elif from_location == "ip_found_in_local_cache_db":
        if isinstance(full_data, list):
            ip_last_checked = datetime.datetime.fromtimestamp(full_data[0][1])
            # Change JSON content from simple quotes to double quotes 
            data_json_with_double_quotes = full_data[0][2].replace("\'", "\"")
        else:
            ip_last_checked = datetime.datetime.now()
            data_json_with_double_quotes = full_data.replace("\'", "\"")

        # Change values that don't have any quotes (except integer values) to have double quotes
        data_json_fixed = fix_json_malformed(data_json_with_double_quotes)
        data_json = json.loads(data_json_fixed)
        ip = data_json['ipAddress']
        isPublic = data_json['isPublic']
        ipVersion = data_json['ipVersion']
        isWhitelisted = data_json['isWhitelisted']
        score = data_json['abuseConfidenceScore']
        country = data_json['countryCode']
        usageType = data_json['usageType']
        isp = data_json['isp']
        domain = data_json['domain']
        hostnames = data_json['hostnames']
        isTor = data_json['isTor']
        totalReports = data_json['totalReports']
        numDistinctUsers = data_json['numDistinctUsers']
        lastReported = data_json['lastReportedAt']
        from_location = "Local cache database"
        format_data_to_log = "From_location: \"" + from_location  + "\"|IP: \"" + str(ip) + "\"|IP_last_checked: \"" + str(ip_last_checked) + "\"|Country_code: \"" + str(country) + "\"|Abuse_confidence_score: \"" + str(score) + "\"|Last_reported_at: \"" + str(lastReported) + "\"|Public_IP: \"" + str(isPublic) + "\"|IP_version: \"" + str(ipVersion) + "\"|Whitelisted: \"" + str(isWhitelisted) + "\"|Usage_type: \"" + str(usageType) + "\"|ISP: \"" + str(isp) + "\"|Domain: \"" + str(domain) + "\"|Hostnames: \"" + str(hostnames) + "\"|Is_TOR: \"" + str(isTor) + "\"|Total_reports: \"" + str(totalReports) + "\"|Number_of_distinct_users: \"" + str(numDistinctUsers) + "\""

    # Remove full_log and previous_log from alert_content ti prevent loop of alerts because some decoders matching with any part of a log
    if 'full_log' in alert_json:
        del alert_json['full_log']
    if 'previous_output' in alert_json:
        del alert_json['previous_output']

    # Log all data collected 
    logging(format_data_to_log + "|Alert_ID: \"" + str(alert_id) + "\"|Alert_content: " + str(alert_json))

def main():
    # Download blacklist
    if sys.argv[1] == "blacklist":
        download_blacklist(blacklist_file)

    # Manage API key in local cache database
    elif sys.argv[1] == "apikey":
        if len(sys.argv) == 3:
            apikey_action = sys.argv[2]
            manage_apikeys(apikey_action, 0)
        elif len(sys.argv) == 4:
            manage_apikeys(sys.argv[2], sys.argv[3])
        else:
            print("Error using apikey command. " + '\n' +
            "Use \"add API_KEY\" to add a API key. Example: " + sys.argv[0] + " apikey add YOUR_API_KEY_HERE" + '\n' +
            "Or use \"remove API_KEY\" to remove a specific API key. Example: "+ sys.argv[0] + " apikey remove YOUR_API_KEY_HERE" + '\n' +
            "Or use \"list\" to view all API keys stored in local cache. Example: " + sys.argv[0] + " apikey list")
            exit(1)

    # Query IP, from alert parsed by Wazuh, on local cache database or AbuseIPDB remote API server
    else:
        get_alert_content()
        local_cache()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        with open(log_file, "a") as f:
            f.write(traceback.format_exc())
            f.close()