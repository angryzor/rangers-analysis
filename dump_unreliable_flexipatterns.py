import sys
import os
import csv

# API_LOCATION = os.environ[rangers_analysis_config['sdk_env_var']]

def dump_unreliable_address_list():
    maps = dict()

    with open('new_addr_map.csv', 'r', newline='') as f:
        for row in csv.reader(f):
            maps[int(row[0])] = (int(row[1]),bool(int(row[2])),int(row[3]))

    # with open(os.path.join(API_LOCATION, 'addresses.csv'), 'r', newline='') as f:
    with open('old_addrs.csv', 'r', newline='') as f:
        with open('new_addrs.csv', 'w', newline='') as of:
            with open('new_unreliable_addrs.csv', 'w', newline='') as ouf:
                csvw = csv.writer(of)
                csvuw = csv.writer(ouf)
                for row in csv.reader(f):
                    addr = int(row[0], 16)
                    name = row[1]
                    if not name.startswith('?Construct@') and addr in maps:
                        mapped_addr, is_reliable, start_addr = maps[addr]
                        if is_reliable:
                            csvw.writerow([f'{start_addr:x}', name, row[2]])
                        else:
                            csvuw.writerow([f'{mapped_addr:x}', name, row[2]])
                    else:
                        print(f"Can't map addr {addr:x} - {name}")

dump_unreliable_address_list()
