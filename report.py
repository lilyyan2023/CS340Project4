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
    #for line in f.readlines():
        #get_ipv4_addresses(url)
        #get_ipv6_addresses(url)
        #get_http_server(url)
        #check_insecure_http(url)
        #get_redirect_to(url)
        #get_hst(url)
        #get_tls_version(url)
        #get_ca(url)
    output_f = open(output, "w")
    output_f.write(information(dict))
    output_f.close()
    #output_f = open(output, "w")
    #json.dump(dict, output_f, sort_keys=True, indent=4)

def sort_tuple_list(l):
    lst = copy.copy(l)
    for i in range(0, len(lst)):
        for j in range(i, len(lst)):
            if lst[i][1] < lst[j][1]:
                tempt = lst[i][1]
                lst[i] = lst[j]
                lst[j] = tempt
    return lst

def root_ca(dict):
    table = Texttable()
    align = ["l"]
    valign = ["t"]
    first_row = ["ca", "occurence"]
    domains = list(dict.keys())
    cas = {}
    for d in domains:
        calst = dict[d]["root_ca"]
        for ca in calst: 
            if ca in list(cas.keys()):
                cas[ca] = cas[ca] + 1
            else:
                cas[ca] = 1
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    rows.append(first_row)
    tuple_list = []
    for ca in cas.keys():
        tuple_list.append((ca, cas[ca]))
    tuple_list = sort_tuple_list(tuple_list)
    for t in tuple_list:
        table.add_rows([t[0], t[1]])
    return table.draw() + "\n"
    

def information(dict):
    table = Texttable()
    align = ["l"]
    valign = ["t"]
    first_row = []
    domains = list(dict.keys())
    headers = list(dict[domains[0]].keys())
    for i in headers:
        align.append("l")
        valign.append("t")
    table.set_cols_align(align)
    table.set_cols_valign(valign)
    rows = []
    first_line = copy.copy(headers)
    first_line.insert(0, "Name")
    rows.append(first_line)
    for d in domains:
        row = []
        row.append(d)
        for h in headers:
            row.append(str(dict[d][h]))
        rows.append(row)
    table.add_rows(rows)
    return table.draw() + "\n"


report(sys.argv[1], sys.argv[2])

