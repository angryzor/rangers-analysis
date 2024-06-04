import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from rangers_analysis.fixups.find_offsets import find_offsets
from rangers_analysis.fixups.fix_functions import fix_functions
from rangers_analysis.fixups.find_strings import find_strings
from rangers_analysis.lib.segments import rdata_seg, text_seg, denuvoized_text_seg

find_offsets(rdata_seg)
fix_functions(rdata_seg, text_seg)
fix_functions(rdata_seg, denuvoized_text_seg)
find_strings(rdata_seg)
