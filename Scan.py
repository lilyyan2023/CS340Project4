import json
import time
import subprocess
import re
import requests
#import http
def scan(input, output):
    dict = {}
    f = open(input, "r")
    public_dns = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6",
                  "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72",
                  "176.103.130.130"]
    for line in f.readlines():
        dict[line] = {"scan_time": time.time()}
        dict[line]["ipv4_addresses"] = []
        dict[line]["ipv6_addresses"] = []
        for dns in public_dns:
            ipv4_add_result = subprocess.check_output(["nslookup", "-type=A", line, dns],
      timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            ipv4_adds = ipv4_add_result.split("\n")[2:]
            for ipv4_add in ipv4_adds:
                if ipv4_add.startswith("Address:"):
                    ipv4_true_add = ipv4_add.split("\t")[1]
                    dict[line]["ipv4_addresses"].append(ipv4_true_add)
            ipv6_add_result = subprocess.check_output(["nslookup", "-type=AAAA", line, dns],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            ipv6_adds = ipv6_add_result.split("\n")[2:]
            for ipv6_add in ipv6_adds:
                if ipv6_add.startswith("Address:"):
                    ipv6_true_add = ipv6_add.split("\t")[1]
                    dict[line]["ipv6_addresses"].append(ipv6_true_add)
        r = requests.get(line)
        if 'server' in r.headers:
            dict[line]["http_server"] = r.headers['server']
        else:
            dict[line]["http_server"] = None
        insecure_http_result = subprocess.check_output(["curl", "-I", line+":80"],
                            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        insecure_http = insecure_http_result.split("\n")
        dict[line]["insecure_http"] = False
        for element in insecure_http:
            if element.startswith("HTTP"):
                dict[line]["insecure_http"] = True















    output_f = open(output, "w")
    json.dump(dict, output_f, sort_keys=True, indent=4)
