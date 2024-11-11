import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

import os
import csv
from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from rangers_analysis.config import rangers_analysis_config
from rangers_analysis.lib.naming import set_generated_name
from rangers_analysis.lib.funcs import require_function, ensure_functions
from rangers_analysis.lib.analysis_exceptions import AnalysisException

API_LOCATION = os.environ[rangers_analysis_config['sdk_env_var']]

def import_unreliable_address_list():
    maps = dict()

    with open('new_addrs.csv', 'r', newline='') as f:
        for row in csv.reader(f):
            maps[int(row[0])] = (int(row[1]),bool(int(row[2])),int(row[3]))

    with open(os.path.join(API_LOCATION, 'addresses.csv'), 'r', newline='') as f:
        for row in csv.reader(f):
            addr = int(row[0], 16)
            if addr in maps:
                try:
                    print(f'Porting old address {addr:x}')
                    mapped_addr, is_reliable, start_addr = maps[addr]
                    if is_reliable:
                        f = ensure_functions(start_addr)
                        set_generated_name(f.start_ea, row[1], certain=int(row[2]) == 1)
                    else:
                        f = require_function(mapped_addr)
                        set_generated_name(f.start_ea, row[1], certain=int(row[2]) == 1)
                except AnalysisException as e:
                    print(f'cant map addr {addr:x} due to error {e}')

import_unreliable_address_list()
