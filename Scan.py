import json
import time
import subprocess
import re
import requests
#import http
dict = {}
def scan(input, output):
    # dict = {}
    f = open(input, "r")
    # public_dns = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6",
    #               "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72",
    #               "176.103.130.130"]
    for line in f.readlines():
      #   dict[line] = {"scan_time": time.time()}
      #   dict[line]["ipv4_addresses"] = []
      #   dict[line]["ipv6_addresses"] = []
      #   for dns in public_dns:
      #       ipv4_add_result = subprocess.check_output(["nslookup", "-type=A", line, dns],
      # timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
      #       ipv4_adds = ipv4_add_result.split("\n")[2:]
      #       for ipv4_add in ipv4_adds:
      #           if ipv4_add.startswith("Address:"):
      #               ipv4_true_add = ipv4_add.split("\t")[1]
      #               dict[line]["ipv4_addresses"].append(ipv4_true_add)
      #       ipv6_add_result = subprocess.check_output(["nslookup", "-type=AAAA", line, dns],
      #           timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
      #       ipv6_adds = ipv6_add_result.split("\n")[2:]
      #       for ipv6_add in ipv6_adds:
      #           if ipv6_add.startswith("Address:"):
      #               ipv6_true_add = ipv6_add.split("\t")[1]
      #               dict[line]["ipv6_addresses"].append(ipv6_true_add)
      #   r = requests.get(line)
      #   if 'server' in r.headers:
      #       dict[line]["http_server"] = r.headers['server']
      #   else:
      #       dict[line]["http_server"] = None
      #   insecure_http_result = subprocess.check_output(["curl", "-I", line+":80"],
      #                       timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
      #   insecure_http = insecure_http_result.split("\n")
      #   dict[line]["insecure_http"] = False
      #   for element in insecure_http:
      #       if element.startswith("HTTP"):
      #           dict[line]["insecure_http"] = True
    output_f = open(output, "w")
    json.dump(dict, output_f, sort_keys=True, indent=4)

def get_scan_time(url):
    global dict
    dict[url] = {"scan_time": time.time()}


def get_ipv4_addresses(url):
    global dict
    dict[url]["ipv4_addresses"] = []
    public_dns = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6",
                  "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72",
                  "176.103.130.130"]
    for dns in public_dns:
        ipv4_add_result = subprocess.check_output(["nslookup", "-type=A", url, dns],
                                                  timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        ipv4_adds = ipv4_add_result.split("\n")[2:]
        for ipv4_add in ipv4_adds:
            if ipv4_add.startswith("Address:"):
                ipv4_true_add = ipv4_add.split("\t")[1]
                dict[url]["ipv4_addresses"].append(ipv4_true_add)
def get_ipv6_addresses(url):
    global dict
    dict[url]["ipv6_addresses"] = []
    public_dns = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6",
                  "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72",
                  "176.103.130.130"]
    for dns in public_dns:
        ipv6_add_result = subprocess.check_output(["nslookup", "-type=AAAA", url, dns],
                                                  timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        ipv6_adds = ipv6_add_result.split("\n")[2:]
        for ipv6_add in ipv6_adds:
            if ipv6_add.startswith("Address:"):
                ipv6_true_add = ipv6_add.split("\t")[1]
                dict[url]["ipv6_addresses"].append(ipv6_true_add)

def get_http_server(url):
    global dict
    r = requests.get(url)
    if 'server' in r.headers:
        dict[url]["http_server"] = r.headers['server']
    else:
        dict[url]["http_server"] = None
def check_insecure_http(url):
    global dict
    insecure_http_result = subprocess.check_output(["curl", "-I", url + ":80"],
                                                   timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    insecure_http = insecure_http_result.split("\n")
    dict[url]["insecure_http"] = False
    for element in insecure_http:
        if element.startswith("HTTP"):
            dict[url]["insecure_http"] = True

def get_redirect_to(url):
    #https://stackoverflow.com/questions/33684356/how-to-capture-the-output-of-openssl-in-python
    lst = openssl_get_header(url)
    if lst != None:
        if int(lst[0][9:11]) == 301:
            return True
        else:
            return False
    else:
        return None

def get_hst(url):
    lst = openssl_get_header(url)
    if lst != None:
        result = False
        for h in lst:
            if h.split(": ")[0] == "Strict-Transport-Security":
                result = h.split(": ")[1]
                result = True
                break
        return result
    else:
        return None

def get_tls_version(url):
    return []


def openssl_get_header(url):
    try:
        req = subprocess.Popen(["openssl", "s_client", "-quiet", "-connect", url+":443"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = req.communicate(bytes("GET / HTTP/1.0\r\nHost: " + url+"\r\n\r\n",encoding="utf-8"), timeout=2)
        output = output.decode(errors='ignore').split("\r\n\r\n")[0].split("\r\n")
        print(output)
        return output
    except Exception as e:
        print(e)
        return None

def openssl_get_TLSv1_3(url):
    try:
        req = subprocess.Popen(["openssl", "s_client", "-tls1_3", "-connect", url+":443"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = req.communicate(timeout=2)
        output = output.decode(errors='ignore')
        print(output)
        return output
    except Exception as e:
        print(e)
        return None

