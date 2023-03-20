#!/var/ossec/framework/python/bin/python3
## Alienvault API Integration
#
import sys
import os
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re
from socket import socket, AF_UNIX, SOCK_DGRAM
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def send_event(msg, agent = None):
    message = f"1:alienvault:{msg}"
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(message.encode())
    sock.close()

# Set the Alienvault OTX API key
api_key = "YOUR_API_KEY"

# Set the API URL and headers
api_url = "https://otx.alienvault.com/api/v1/indicators/domain/{0}"
headers = {
    "Content-Type": "application/json",
    "X-OTX-API-KEY": api_key
}

# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if Alienvault Alert or Error calling the API
alert_output = {}

## Extract Domain from DNSStats Alert
dns_requested = alert["data"]["dnsstat"]["query"]

# Make the request to the API
try:
    response = requests.get(api_url.format(dns_requested), headers=headers, verify=True)
    response.raise_for_status()
    data = response.json()
    
    # Extract the desired values from the response
    sections = data["sections"]
    indicator_type = data["type"]
    base_indicator = data["base_indicator"]
    
    # Build the alert output dictionary
    alert_output = {
        "status": "success",
        "message": "Alienvault OTX API response successfully parsed",
        "sections": sections,
        "type": indicator_type,
        "base_indicator": base_indicator,
        "dns_requested": dns_requested
    }
except requests.exceptions.RequestException as e:
    # Request error
    alert_output = {
        "status": "error",
        "message": "Error connecting to Alienvault OTX API: {0}".format(str(e))
    }
except Exception as e:
    # Other error
    alert_output = {
        "status": "error",
        "message": "Error checking domain against Alienvault OTX API: {0}".format(str(e))
    }

# Send the alert output to the OSSEC server
send_event(json.dumps(alert_output))
