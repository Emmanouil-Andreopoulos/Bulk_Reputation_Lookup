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
        print('     "output_filename" : "output_list.txt",')
        print('     "VT_API_KEYS_filename" : "VT_API_KEYS.txt",')
        print('     "AIP_API_KEYS_filename" : "AIP_API_KEYS.txt"')
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


def vt_ip_lookup(ip_to_check, provider_counter):
    api_key = get_api_key("VT", provider_counter)
    print(api_key)


def aip_ip_lookup(ip_to_check, provider_counter):
    api_key = get_api_key("AIP", provider_counter)
    print(api_key)


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


def ip_lookup():
    ip_addresses_length = len(IP_Addresses)
    ip_counter = 0
    vt_counter = -1
    aip_counter = -1
    for ip_address in IP_Addresses:
        ip_counter += 1
        if enable_VT or enable_AbuseIP:
            print(f"({ip_counter}/{ip_addresses_length}) Checking {ip_address}...")
        if enable_VT:
            vt_counter = get_provider_counter("VT", vt_counter)
            vt_ip_lookup(ip_address, vt_counter)
        if enable_AbuseIP:
            aip_counter = get_provider_counter("AIP", aip_counter)
            aip_ip_lookup(ip_address, aip_counter)


if __name__ == '__main__':
    # Read configuration file
    init_configuration()
    # Read API KEYS from file
    init_api_keys()
    # Read input file and add IP addresses to list
    read_input_file()
    # Start Lookup
    ip_lookup()
