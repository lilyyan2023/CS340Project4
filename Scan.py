import json
import time
import subprocess
import re
import requests
import maxminddb
import socket
import sys
#import http
dict = {}
def scan(input, output):
    f = open(input, "r")
    for line in f.readlines():
        url = line.replace("\n", "")
        print(url)
        dict[url] = {}
        rtt_value = []
        #get_scan_time(url)
        get_ipv4_addresses(url)
        #get_ipv6_addresses(url)
        #get_http_server(url)
        #check_insecure_http(url)
        #get_redirect_to(url)
        #get_hst(url)
        #get_tls_version(url)
        #get_ca(url)
        #get_rdns_names(url)
        rtt_value = get_rtt_value(url)
        if rtt_value != None:
            rtt_value.sort()
            print(rtt_value)
            dict[url]["rtt_range"] = [rtt_value[0], rtt_value[-1]]
        else:
            dict[url]["rtt_range"] = [None, None]
        #dict[url]["geo_locations"] = get_geo_location(url)
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
    try:
        for dns in public_dns:
            ipv4_add_result = subprocess.check_output(["nslookup", "-type=A", url, dns],
                                                          timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
            ipv4_adds = ipv4_add_result.split("\n")[2:]
            for ipv4_add in ipv4_adds:
                if ipv4_add.startswith("Address:"):
                    ipv4_true_add = ipv4_add.split(" ")[1]
                    if ipv4_true_add not in dict[url]["ipv4_addresses"]:
                        dict[url]["ipv4_addresses"].append(ipv4_true_add)
    except Exception as e:
        print(e, file=sys.stderr)


def get_ipv6_addresses(url):
    global dict
    dict[url]["ipv6_addresses"] = []
    public_dns = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6",
                  "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72",
                  "176.103.130.130"]
    try:
        for dns in public_dns:
            ipv6_add_result = subprocess.check_output(["nslookup", "-type=AAAA", url, dns],
                                                      timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
            ipv6_adds = ipv6_add_result.split("\n")[2:]
            for ipv6_add in ipv6_adds:
                if ipv6_add.startswith("Address:"):
                    ipv6_true_add = ipv6_add.split(" ")[1]
                    if ipv6_true_add not in dict[url]["ipv6_addresses"]:
                        dict[url]["ipv6_addresses"].append(ipv6_true_add)
    except Exception as e:
        print(e, file=sys.stderr)

def get_http_server(url):
    global dict
    try:
        r = requests.get("http://"+url, timeout=5)
        if 'server' in r.headers:
            dict[url]["http_server"] = r.headers['server']
        else:
            dict[url]["http_server"] = None
    except Exception as e:
        print(e, file=sys.stderr)


def check_insecure_http(url):
    global dict
    try:
        insecure_http_result = subprocess.check_output(["curl", "-I", url + ":80"],
                                                       timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
        insecure_http = insecure_http_result.split("\n")
        dict[url]["insecure_http"] = False
        for element in insecure_http:
            if element.startswith("HTTP"):
                dict[url]["insecure_http"] = True
    except Exception as e:
        print(e, file=sys.stderr)

def get_redirect_to(url):
    global dict
    #https://stackoverflow.com/questions/33684356/how-to-capture-the-output-of-openssl-in-python
    lst = openssl_get_header(url)
    if lst != None:
        if int(lst[0][9:12]) == 301:
            dict[url]["redirect_to_https"] = True
        else:
            dict[url]["redirect_to_https"] = False
    else:
        return None

def get_hst(url):
    global dict
    lst = openssl_get_header(url)
    if lst != None:
        while int(lst[0][9:12]) == 301:
            location = ""
            for h in lst:
                if h.split(": ")[0] == "Location":
                    location = h.split(": ")[1]
                    break
            if location == "":
                break
            if "://" in location:
                location = location.split("://")[1]
            print(location)
            if location[-1] == "/":
                location = location[0:len(location)-1]
            lst = openssl_get_header(location)
        result = False
        for h in lst:
            if h.split(": ")[0] == "Strict-Transport-Security":
                result = True
                break
        dict[url]["hsts"] = result
    else:
        return None

def get_tls_version(url):
    global dict
    result = []
    tls = nmap_get_TLS(url)
    if tls != None:
        result = tls
    if openssl_get_TLSv1_3(url):
        result.append("TLSv1.3")
    dict[url]["tls_versions"] = result

def get_ca(url):
    result = openssl_get_ca(url)
    if result != None:
        dict[url]["root_ca"] = result


def openssl_get_header(url):
    try:
        #print(url)
        root = url.split("/")[0]
        #print(root)
        req = subprocess.Popen(["openssl", "s_client", "-quiet", "-connect", root+":443"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = req.communicate(bytes("GET / HTTP/1.0\r\nHost: " + url+"\r\n\r\n",encoding="utf-8"), timeout=2)
        output = output.decode(errors='ignore').split("\r\n\r\n")[0].split("\r\n")
        #print(output)
        return output
    except subprocess.TimeoutExpired:
        print("Subprocess Timeout", file=sys.stderr)
        return None
    except Exception as e:
        print(e, file=sys.stderr)
        return None

def nmap_get_TLS(url):
    try:
        TLS_lst = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"]
        req = subprocess.Popen(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", url],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = req.communicate(timeout=10)
        output = output.decode()
        lst = output.split('\n|')
        result = []
        for h in lst:
            if h.strip().split(":")[0] in TLS_lst:
                result.append(h.strip().split(":")[0])
        return result
    except subprocess.TimeoutExpired:
        print("Subprocess Timeout", file=sys.stderr)
        return None
    except Exception as e:
        print(e, file=sys.stderr)
        return None

def openssl_get_TLSv1_3(url):
    try:
        req = subprocess.Popen(["openssl", "s_client", "-tls1_3", "-connect", url+":443"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = req.communicate(timeout=2)
        output = output.decode(errors='ignore')
        if "TLSv1.3" in output.split(", "):
            return True
        else:
            return False
    except subprocess.TimeoutExpired:
        print("Subprocess Timeout", file=sys.stderr)
        return None
    except Exception as e:
        print(e, file=sys.stderr)
        return None

def openssl_get_ca(url):
    try:
        req = subprocess.Popen(["openssl", "s_client", "-connect", url+":443"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = req.communicate(timeout=5)
        output = output.decode(errors='ignore').split("---\n")
        for line in output:
            if line[0:17] == "Certificate chain":
                result = line.split("O = ")[-1].split(",")[0]
                return result
        return None
    except subprocess.TimeoutExpired:
        print("Subprocess Timeout", file=sys.stderr)
        return None
    except Exception as e:
        print(e, file=sys.stderr)
        return None

def get_rdns_names(url):
    global dict
    dict[url]["rdns_names:"] = []
    # extract ipv4_add from part B
    try:
        for ipv4_add in dict[url]["ipv4_addresses"]:
            rdns_result = subprocess.check_output(["dig", "-x", ipv4_add],
                                                           timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
            rdns_list = rdns_result.split("\n")
            if ";; ANSWER SECTION:" in rdns_list:
                i = 0
                while i < len(rdns_list):
                    if rdns_list[i] == ";; ANSWER SECTION:":
                        start = i
                        rdns_list = rdns_list[start + 1::]
                    i += 1
                j = 0
                while j < len(rdns_list):
                    if rdns_list[j].startswith(";;"):
                        rdns_list = rdns_list[:j - 1]
                    j += 1
                print(rdns_list)
                for line in rdns_list:
                    rdns_element = line.split("\t")
                    k = 0
                    while k < len(rdns_element):
                        if rdns_element[k] == "PTR":
                            rdns_name = rdns_element[k + 1][:-1]
                            dict[url]["rdns_names:"].append(rdns_name)
                        k += 1

    except Exception as e:
        print(e, file=sys.stderr)


def get_rtt_value(url):
    # return one single rtt value
    rtt_value = []
    try:
        for ipv4_add in dict[url]["ipv4_addresses"]:
            ipv4_add_str = str(ipv4_add)    
            sock_params = (ipv4_add_str, 443)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                t1 = time.time()
                sock.connect(sock_params)
                t2 = time.time()
                rtt_value.append(t2 - t1)
            # ipv4_add_str = str(ipv4_add)
            # rtt_result = subprocess.check_output(["sh", "-c",'"time echo -e', "'\x1dclose\x0d'" , '| telnet' ,ipv4_add_str, '443"']
            #                               , timeout = 5, stderr = subprocess.STDOUT).decode("utf-8")
            # for element in rtt_result.split("\n"):
            #     if element.startswith("real"):
            #         rtt_value.append(element.split("\t")[1])
        return rtt_value

    except Exception as e:
        print(e, file=sys.stderr)
        return None

def get_geo_location(url):
    # return single geo_location, need to remove duplicate in result list
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    geo_locations = []
    for	ipv4_add in dict[url]["ipv4_addresses"]:
        geo_locations_result = reader.get(ipv4_add)
        print(geo_locations_result)
        if 'subdivisions' in geo_locations_result and 'city' in geo_locations_result:
            geo_location = [geo_locations_result['city']['names']['en'],
                         geo_locations_result['subdivisions'][0]['names']['en'],
                         geo_locations_result['country']['names']['en']]
        elif 'subdivision' in geo_locations_result:
            geo_location = [geo_locations_result['subdivisions'][0]['names']['en']
                        ,geo_locations_result['country']['names']['en']]
        else:
            geo_location = [geo_locations_result['country']['names']['en']]
        if geo_location not in geo_locations:    
            geo_locations.append(geo_location)
    return geo_locations



scan(sys.argv[1], sys.argv[2])

