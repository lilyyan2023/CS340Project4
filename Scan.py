import json

def scan(input, output):
    dict = {}
    f = open(input, "r")
    for line in f.readlines():
        dict[line] = {}

    output_f = open(output, "w")
    json.dump(dict, output_f, sort_keys=True, indent=4)
