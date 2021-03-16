import json
import time
import subprocess
import re
import requests
import maxminddb
from texttable import Texttable
import copy

import sys
#import http

def report(input, output):
    f = open(input, "r")
    dict = json.load(f)
    output_f = open(output, "w")
    output_f.write(information(dict)+rtt(dict)+root_ca(dict)+web_server(dict))
    output_f.close()

def sort_tuple_list(l):
    lst = copy.copy(l)
    for i in range(0, len(lst)):
        for j in range(i, len(lst)):
            if lst[i][1] < lst[j][1]:
                tempt = lst[i]
                lst[i] = lst[j]
                lst[j] = tempt
    return lst

def sort_tuple_list_rtt(l):
    lst = copy.copy(l)
    for i in range(0, len(lst)):
        for j in range(i, len(lst)):
            if lst[i][1] > lst[j][1]:
                tempt = lst[i]
                lst[i] = lst[j]
                lst[j] = tempt
    return lst


def rtt(dict):
    table = Texttable()
    align = ["l","c"]
    valign = ["t","t"]
    first_row = ["domain", "rtt"]
    domains = list(dict.keys())
    rtt = {}
    for d in domains:
        if "rtt_range" in list(dict[d].keys()) and dict[d]["rtt_range"][0] != None:
            rtt[d] = dict[d]["rtt_range"]
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    rows = []
    rows.append(first_row)
    tuple_list = []
    for d in rtt.keys():
        tuple_list.append([d, rtt[d]])
    tuple_list = sort_tuple_list_rtt(tuple_list)
    for t in tuple_list:
        rows.append([t[0], t[1]])
    table.add_rows(rows)
    return table.draw() + "\n"

def root_ca(dict):
    table = Texttable()
    align = ["l","c"]
    valign = ["t","t"]
    first_row = ["ca", "occurence"]
    domains = list(dict.keys())
    cas = {}
    for d in domains:
        if "root_ca" in list(dict[d].keys()):
            ca = dict[d]["root_ca"]
            if ca in list(cas.keys()):
                cas[ca] = cas[ca] + 1
            else:
                cas[ca] = 1
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    rows = []
    rows.append(first_row)
    tuple_list = []
    for ca in cas.keys():
        tuple_list.append([ca, cas[ca]])
    tuple_list = sort_tuple_list(tuple_list)
    for t in tuple_list:
        rows.append([t[0], t[1]])
    table.add_rows(rows)
    return table.draw() + "\n"
    
def web_server(dict):
    table = Texttable()
    align = ["l","c"]
    valign = ["t","t"]
    first_row = ["http server", "occurence"]
    domains = list(dict.keys())
    cas = {}
    for d in domains:
        if "http_server" in list(dict[d].keys()):
            ca = dict[d]["http_server"]
            if ca in list(cas.keys()):
                cas[ca] = cas[ca] + 1
            else:
                cas[ca] = 1
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    rows = []
    rows.append(first_row)
    tuple_list = []
    for ca in cas.keys():
        tuple_list.append([ca, cas[ca]])
    tuple_list = sort_tuple_list(tuple_list)
    for t in tuple_list:
        rows.append([t[0], t[1]])
    table.add_rows(rows)
    return table.draw() + "\n"

def information(dict):
    table = Texttable()
    align = ["l"]
    valign = ["t"]
    first_row = []
    domains = list(dict.keys())
    headers = ["scan_time", "ipv4_addresses", "ipv6_addresses", "http_server", "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]
    for i in headers:
        align.append("l")
        valign.append("t")
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    table.set_cols_width([10, 10, 20, 30, 10, 5, 5, 10, 10, 10, 10, 10, 10])
    rows = []
    first_line = copy.copy(headers)
    first_line.insert(0, "Name")
    rows.append(first_line)
    for d in domains:
        row = []
        row.append(d)
        for h in headers:
            if h in list(dict[d].keys()):
                row.append(str(dict[d][h]))
            else:
                row.append("")
        rows.append(row)
    table.add_rows(rows)
    return table.draw() + "\n"

def percentage(dict):
    TLS_lst = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    total = len(list(dict.keys()))
    sslv2 = 0
    sslv3 = 0
    tls0 = 0
    tls1 = 0
    tls2 = 0
    tls3 = 0
    plain = 0
    redirect = 0
    hsts = 0
    ipv6 = 0
    for k in dict.keys():
        if "SSLv2" in dict[k]["tls_versions"]:
            sslv2 += 1
        if "SSLv3" in dict[k]["tls_versions"]:
            sslv3 += 1
        if "TLSv1.0" in dict[k]["tls_versions"]:
            tls0 += 1
        if "TLSv1.1" in dict[k]["tls_versions"]:
            tls1 += 1
        if "TLSv1.2" in dict[k]["tls_versions"]:
            tls2 += 1
        if "TLSv1.3" in dict[k]["tls_versions"]:
            tls3 += 1
        if dict[k]["insecure_http"]:
            plain += 1
        if dict[k]["redirect_to_https"]:
            redirect += 1
        if dict[k]["hsts"]:
            hsts += 1
        if dict[k][ipv6_addresses] != []:
            ipv6 += 1
    table = Texttable()
    align = ["l", "c"]
    valign = ["t", "t"]
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    rows = [["Name", "Percentage"],
            ["SSlv2", int(sslv2/total*100)],
            ["SSlv3", int(sslv3/total*100)],
            ["TLSv1.0", int(tls0/total*100)],
            ["TLSv1.1", int(tls1/total*100)],
            ["TLSv1.2", int(tls2/total*100)],
            ["TLSv1.3", int(tls3/total*100)],
            ["plain http", int(plain/total*100)],
            ["https redirect", int(redirect/total*100)], 
            ["hsts", int(hsts/total*100)],
            ["ipv6", int(ipv6/total*100)]]
    table.add_rows(rows)
    return table.draw() + "\n"
report(sys.argv[1], sys.argv[2])

