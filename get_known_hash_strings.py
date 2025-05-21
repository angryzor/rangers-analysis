import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from ida_name import get_name
from ida_ua import o_mem

from rangers_analysis.lib.ua_data_extraction import find_insn_backward, find_insn_forward
from rangers_analysis.lib.funcs import require_function, require_thunk
from rangers_analysis.lib.util import require_name_ea, get_cstr
from rangers_analysis.lib.xrefs import get_safe_crefs_to
from rangers_analysis.lib.analysis_exceptions import AnalysisException

hashstr_func = require_function(require_name_ea('hashstring'))

for xref in get_safe_crefs_to(hashstr_func.start_ea):
    try:
        f = require_function(xref)
        id_insn = find_insn_backward(lambda insn: insn.mnem == 'lea' and insn.insn.Op1.reg == 2, xref, f.start_ea)

        if id_insn.insn.Op2.type != o_mem:
            raise AnalysisException('not direct memory pointer')

        print(f'{xref:x}: {get_cstr(id_insn.insn.Op2.addr - 1)}')
    except AnalysisException as e:
        print(f'{xref:x}: err: {e}')
    except Exception as e:
        print(f'{xref:x}: err unknown - {e}')
