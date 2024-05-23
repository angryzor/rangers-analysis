import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import configure_rangers_analysis

configure_rangers_analysis('wars', 'latest')

from rangers_analysis.fixups.find_offsets import find_offsets
from rangers_analysis.fixups.fix_functions import fix_functions
from rangers_analysis.fixups.find_strings import find_strings
from rangers_analysis.lib.segments import rdata_seg, text_seg, denuvoized_text_seg
from rangers_analysis.informed_analysis.report import clear_report, print_report
from rangers_analysis.informed_analysis.standard_analysis import run_standard_analysis
from rangers_analysis.informed_analysis.extensive_analysis import run_extensive_analysis

# find_offsets(rdata_seg)
# fix_functions(rdata_seg, text_seg)
# fix_functions(rdata_seg, denuvoized_text_seg)
# find_strings(rdata_seg)

clear_report()

run_standard_analysis()
# run_extensive_analysis()

print_report()
