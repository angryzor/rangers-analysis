import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from rangers_analysis.fixups.find_offsets import find_offsets
from rangers_analysis.fixups.fix_functions import fix_functions
from rangers_analysis.fixups.find_strings import find_strings
from rangers_analysis.lib.segments import rdata_seg, data_seg, text_seg, denuvoized_text_seg

from ida_segment import get_segm_by_name

find_offsets(get_segm_by_name(rdata_seg))
if denuvoized_text_seg:
    fix_functions(get_segm_by_name(rdata_seg), get_segm_by_name(text_seg))
    fix_functions(get_segm_by_name(rdata_seg), get_segm_by_name(denuvoized_text_seg))
find_offsets(get_segm_by_name(data_seg))
if denuvoized_text_seg:
    fix_functions(get_segm_by_name(data_seg), get_segm_by_name(text_seg))
    fix_functions(get_segm_by_name(data_seg), get_segm_by_name(denuvoized_text_seg))
find_strings(get_segm_by_name(rdata_seg))
# find_offsets(get_segm_by_name(rdata_seg))
