import sys
import os
import csv

# API_LOCATION = os.environ[rangers_analysis_config['sdk_env_var']]

def dump_unreliable_address_list():
    old = dict()
    new = dict()
    addrs = set()

    with open(sys.argv[1], 'r', newline='') as f:
        for row in csv.reader(f):
            addr = int(row[0], 16)
            name = row[1]
            old[addr] = name
            addrs.add(addr)

    with open(sys.argv[2], 'r', newline='') as f:
        for row in csv.reader(f):
            addr = int(row[0], 16)
            name = row[1]
            new[addr] = name
            addrs.add(addr)

    addrs_sorted = [*addrs].sort()
    
    with open('addr_diff.csv', 'w', newline='') as of:
        csvw = csv.writer(of)
        for addr in addrs:
            if addr in new and (addr not in old or old[addr] != new[addr]):
                csvw.writerow([f'{addr:x}', old[addr] if addr in old else '', new[addr] if addr in new else ''])


dump_unreliable_address_list()
