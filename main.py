import json
import re
import requests

# Default Configuration
enable_VT = False
enable_AbuseIP = False
IP_Addresses = list()
VT_API_KEYS = list()
AIP_API_KEYS = list()
input_filename = "input_list.txt"
output_filename = "output_list.txt"
VT_API_KEYS_filename = "VT_API_KEYS.txt"
AIP_API_KEYS_filename = "AIP_API_KEYS.txt"
delimiter = ";"


def init_configuration():
    try:
        with open("configuration.json", "r") as jsonfile:
            configuration = json.load(jsonfile)
    except FileNotFoundError:
        print("Configuration file not found!\n\nExample of json configuration file:\n")
        print("{")
        print('     "enable_VT" : "True",')
        print('     "enable_AbuseIP" : "True",')
        print('     "input_filename" : "input_list.txt",')
        print('     "output_filename" : "output_list.csv",')
        print('     "VT_API_KEYS_filename" : "VT_API_KEYS.txt",')
        print('     "AIP_API_KEYS_filename" : "AIP_API_KEYS.txt",')
        print('     "delimiter" : ";"')
        print("}")
        quit()

    if configuration["enable_VT"].casefold() == "True".casefold():
        global enable_VT
        enable_VT = True

    if configuration["enable_AbuseIP"].casefold() == "True".casefold():
        global enable_AbuseIP
        enable_AbuseIP = True

    if configuration["input_filename"].casefold() != "".casefold():
        global input_filename
        input_filename = configuration["input_filename"]

    if configuration["output_filename"].casefold() != "".casefold():
        global output_filename
        output_filename = configuration["output_filename"]

    if configuration["input_filename"].casefold() != "".casefold():
        global VT_API_KEYS_filename
        VT_API_KEYS_filename = configuration["VT_API_KEYS_filename"]

    if configuration["input_filename"].casefold() != "".casefold():
        global AIP_API_KEYS_filename
        AIP_API_KEYS_filename = configuration["AIP_API_KEYS_filename"]

    if configuration["delimiter"].casefold() != "".casefold():
        global delimiter
        delimiter = configuration["delimiter"]


def init_api_keys():
    # VirusTotal API KEYS
    with open(VT_API_KEYS_filename, "r") as vt_file:
        for line in vt_file:
            global VT_API_KEYS
            VT_API_KEYS.append(line.replace('\n', ''))
    # AbuseIPDB API KEYS
    with open(AIP_API_KEYS_filename, "r") as AIP_file:
        for line in AIP_file:
            global AIP_API_KEYS
            AIP_API_KEYS.append(line.replace('\n', ''))


def read_input_file():
    # Regular expression for IP addresses
    IP_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    with open(input_filename, "r") as input_file:
        for line in input_file:
            match = re.search(IP_regex, line)
            if match:
                global IP_Addresses
                IP_Addresses.append(match.group())


def get_api_key(provider, provider_counter):
    if provider == "VT":
        return VT_API_KEYS[provider_counter]
    elif provider == "AIP":
        return AIP_API_KEYS[provider_counter]


def get_provider_counter(provider, provider_counter):
    api_keys_length = 0
    if provider == "VT":
        api_keys_length = len(VT_API_KEYS)
    elif provider == "AIP":
        api_keys_length = len(AIP_API_KEYS)
    else:
        quit()

    provider_counter += 1
    if provider_counter >= api_keys_length:
        provider_counter = 0

    return provider_counter


def vt_ip_lookup(ip_to_check, provider_counter):
    api_key = get_api_key("VT", provider_counter)
    response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_to_check}",
                            headers={"x-apikey": api_key, "Accept": "application/json"})
    result = response.json().get("data").get("attributes").get("last_analysis_stats")
    f_result = delimiter + str(result["malicious"]) + delimiter + str(result["suspicious"]) + delimiter + \
               str(result["harmless"]) + delimiter + str(result["undetected"]) + delimiter + str(result["timeout"])
    return f_result


def aip_ip_lookup(ip_to_check, provider_counter):
    api_key = get_api_key("AIP", provider_counter)
    response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_to_check}",
                            headers={"Key": api_key, "Accept": "application/json"})
    result = response.json().get("data")
    f_result = delimiter + str(result["abuseConfidenceScore"]) + delimiter + \
               str(result["totalReports"]) + delimiter + str(result["countryCode"])
    return f_result


def ip_lookup():
    ip_addresses_length = len(IP_Addresses)
    ip_counter = 0
    vt_counter = -1
    aip_counter = -1
    out_file = open(output_filename, "w")
    file_header = "IP Address"
    if enable_AbuseIP:
        file_header += delimiter + "abuseConfidenceScore" + delimiter + "totalReports" + delimiter + "countryCode"
    if enable_VT:
        file_header += delimiter + "malicious" + delimiter + "suspicious" + delimiter + "harmless" + delimiter + "undetected" + delimiter + "timeout"
    out_file.write(file_header + delimiter + "\n")
    for ip_address in IP_Addresses:
        ip_counter += 1
        final_response = ip_address
        if enable_VT or enable_AbuseIP:
            print(f"({ip_counter}/{ip_addresses_length}) Checking {ip_address}...")
        if enable_AbuseIP:
            aip_counter = get_provider_counter("AIP", aip_counter)
            final_response += str(aip_ip_lookup(ip_address, aip_counter))
        if enable_VT:
            vt_counter = get_provider_counter("VT", vt_counter)
            final_response += str(vt_ip_lookup(ip_address, vt_counter))
        out_file.write(final_response + delimiter + "\n")
    out_file.close()


if __name__ == '__main__':
    # Read configuration file
    init_configuration()
    # Read API KEYS from file
    init_api_keys()
    # Read input file and add IP addresses to list
    read_input_file()
    # Start Lookup
    ip_lookup()
