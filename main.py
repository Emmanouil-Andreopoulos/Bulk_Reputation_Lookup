import json
import re
import requests

enable_VT = False
enable_AbuseIP = False
IP_Addresses = list()
input_filename = "input_list.txt"


def init_configuration():
    try:
        with open("configuration.json", "r") as jsonfile:
            configuration = json.load(jsonfile)
    except FileNotFoundError:
        print("Configuration file not found")
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


def read_input_file():
    # Regular expression for IP addresses
    IP_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    with open(input_filename, "r") as input_file:
        for line in input_file:
            match = re.search(IP_regex, line)
            if match:
                IP_Addresses.append(match.group())


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    init_configuration()
    read_input_file()
    print(enable_VT)
    print(enable_AbuseIP)
    print(input_filename)
