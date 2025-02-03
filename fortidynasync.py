# FortiDynaSync
# © 2025 JJGadgets (https://jjgadgets.tech) (https://social.jjgadgets.tech/@jj) (https://github.com/JJGadgets)
# Licensed under GNU AGPL v3.0.0 as per LICENSE file in https://github.com/JJGadgets/FortiDynaSync
# NOT AFFILIATED WITH OR AN OFFICIAL PRODUCT/SERVICE BY FORTINET.

# NOTES:
# You need an API key with Admin Profile allowing R/O on Network/Configuration, and R/W on System/Configuration.
# If only they had more granular API authz, such as by path and method. *siiiiiigh*.

from os import environ
import requests
from typing import TextIO
from operator import itemgetter

# type enforcement functions

def openRO(file: str) -> TextIO:
    return open(file, "r", encoding="utf-8")

def getEnv(env: str) -> str:
    return str(environ.get(env))

# functions for variables

def readFileOrEnv(env: str, defaultPath: bool = True) -> str:
    file: str = f"{env}_FILE"
    defaultFile: str = "/secrets/" + env.lower()
    if environ.get(file) is not None:
        return str(openRO(getEnv(file)).read())
    elif environ.get(env) is not None:
        return str(getEnv(env))
    elif defaultPath:
        try:
            return str(openRO(defaultFile).read())
        except Exception:
            return ""
    else:
        return ""

# variables

fgtHost: str = readFileOrEnv("FGT_HOST") or "192.168.1.99"
fgtPort: str = readFileOrEnv("FGT_PORT") or "443"
fgtVerifyTLS: bool = getEnv("FGT_VERIFY_TLS") == "True" or False
fgtZone: str = readFileOrEnv("FGT_ZONE") or "dhcp.internal"
fgtVdom: str = readFileOrEnv("FGT_VDOM") or "root"
fgtIPv6: bool = getEnv("FGT_IPV6") == "True" or True
fgtIPv6Str: str = str(fgtIPv6).lower()
fgtLogRecords: bool = getEnv("FGT_LOG_RECORDS") == "True" or False

try:
    fgtApiKey: str = readFileOrEnv("FGT_API_KEY")
except Exception:
    raise Exception("Environment variable 'FGT_API_KEY' not found!")

fgtTTL: int = 0
try:
    fgtTTL = int(readFileOrEnv("FGT_TTL")) or 0
except Exception:
    pass

# Stage 1: get DHCP clients from FortiGate

dhcpKeys = {"ip", "hostname", "interface", "type"}
dhcpClientsUrl = f"https://{fgtHost}:{fgtPort}/api/v2/monitor/system/dhcp?ipv6={fgtIPv6Str}&vdom={fgtVdom}"
dhcpClientsHeaders = {"Authorization": f"Bearer {fgtApiKey}", "Accept": "application/json"}
try:
    dhcpClients = sorted([{k:v for k,v in i.items() if k in dhcpKeys} for i in requests.get(url = dhcpClientsUrl, headers = dhcpClientsHeaders, verify = fgtVerifyTLS).json()['results'] if "hostname" in i.keys()], key = itemgetter("interface", "hostname", "type", "ip")) # pyright: ignore[reportAny]
except Exception:
    raise Exception(requests.get(url = dhcpClientsUrl, headers = dhcpClientsHeaders, verify = fgtVerifyTLS).text)

# Stage 2: parse

def checkDNStype(ipType: str) -> str:
    if ipType == "ipv4":
        return "A"
    elif ipType == "ipv6":
        return "AAAA"
    else:
        raise Exception(f"Cannot parse DNS type for IP type '{ipType}'!")

dnsRecords: dict[str, list[dict[str, str | int]]] = {"dns-entry": []}
for i in range(len(dhcpClients)):
    v: dict[str, str] = dhcpClients[i]
    dnsRecords["dns-entry"].insert(i, {
        "id": i + 1,
        "status": "enable",
        "ttl": fgtTTL,
        "preference": 10,
        "hostname": str(v['hostname']) + "." + str(v['interface']),
        "ip": str(v['ip']),
        "type": checkDNStype(v['type'])
    })
del dhcpClients

if fgtLogRecords:
    print("")
    print(f"Syncing the following DNS database to FortiGate {fgtHost} DNS server zone '{fgtZone}':")
    print(dnsRecords)
    print("")

# Stage 3: upload

reqUrl = f"https://{fgtHost}:{fgtPort}/api/v2/cmdb/system/dns-database/{fgtZone}?vdom={fgtVdom}"
reqHeaders = {"Authorization": f"Bearer {fgtApiKey}", "Content-Type": "application/json"}

req1 = requests.put(url = reqUrl, headers = reqHeaders, json = dnsRecords, verify = fgtVerifyTLS)
if req1.status_code != 200:
    req2 = requests.post(url = reqUrl, headers = reqHeaders, json = dnsRecords, verify = fgtVerifyTLS)
    if req2.status_code != 200:
        print("PUT request failed with response: " + req1.text)
        print("POST request failed with response: " + req2.text)
        raise Exception("Failed to upload DNS records of DHCP clients to FortiGate!")
else:
    print(f"Finished syncing DNS records of DHCP clients to FortiGate {fgtHost} DNS server at DNS zone {fgtZone}, bye bye!")
