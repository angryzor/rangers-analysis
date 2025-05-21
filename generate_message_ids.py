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
from rangers_analysis.lib.util import require_name_ea
from rangers_analysis.lib.xrefs import get_safe_crefs_to
from rangers_analysis.lib.analysis_exceptions import AnalysisException

msg_ctor = require_thunk(require_function(require_name_ea('??0Message@fnd@hh@@QEAA@W4MessageID@12@@Z')))

for xref in get_safe_crefs_to(msg_ctor.start_ea):
    try:
        f = require_function(xref)
        id_insn = find_insn_backward(lambda insn: insn.mnem == 'mov' and insn.insn.Op1.reg == 2, xref, f.start_ea)
        vtable_insn = find_insn_forward(lambda insn: insn.mnem == 'lea' and insn.insn.Op2.type == o_mem and get_name(insn.insn.Op2.addr).startswith('??_7'), xref, f.end_ea)

        print(f'{id_insn.insn.Op2.value},{get_name(vtable_insn.insn.Op2.addr)}')
    except AnalysisException as e:
        print(f'err: {e}')
    except:
        print(f'err doing {xref:x}')
