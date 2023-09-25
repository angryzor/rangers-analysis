import sys

analmodules = [mod for mod in sys.modules if mod.startswith('analrangers')]
for mod in analmodules:
    del sys.modules[mod]

from ida_bytes import get_qword, get_dword, get_byte
from ida_funcs import get_func
from ida_ua import o_reg
from ida_name import get_name, get_demangled_name, MNG_SHORT_FORM, MNG_NOTYPE
from analrangers.lib.util import require_type, require_name_ea, require_cstr, force_apply_tinfo, force_apply_tinfo_array
from analrangers.lib.iterators import require_unique, null_terminated_ptr_array_iterator
from analrangers.lib.heuristics import discover_class_hierarchy, estimate_class_name_from_constructor
from analrangers.lib.funcs import require_function, set_func_name, ensure_functions, find_unique_thunk
from analrangers.lib.xrefs import get_code_drefs_to
from analrangers.lib.analysis_exceptions import AnalException
from analrangers.lib.ua_data_extraction import read_insn, read_source_op_addr, read_source_op_addr_from_reg_assignment, read_source_op_addr_from_mem_assignment_through_single_reg, read_source_op_imm_from_mem_assignment, decoded_insns_backward
from analrangers.informed_analysis.report import handle_anal_exceptions, print_report, clear_report
from analrangers.informed_analysis.static_initializers import find_static_initializers
from datetime import datetime
from collections import OrderedDict
import os
import ctypes


class_tif = require_type('hh::game::GOComponentClass')

f = open(f'rangers-classes.txt', 'w')

for instantiator_thunk, instantiator_func, ctor_thunk, ctor_func, base_ctor_func in discover_class_hierarchy(require_function(require_name_ea('hh::game::GameService::GameService'))):
    name = estimate_class_name_from_constructor(ctor_func) or get_demangled_name(ctor_func.start_ea, MNG_SHORT_FORM, 0)
    base_name = estimate_class_name_from_constructor(base_ctor_func) or get_demangled_name(base_ctor_func.start_ea, MNG_SHORT_FORM, 0)

    f.write(f'{instantiator_func.start_ea if instantiator_func else 0:016x}/{ctor_func.start_ea:016x} -- {"*" if instantiator_func == ctor_func else " "} {name} : {base_name}\n')

f.close()
