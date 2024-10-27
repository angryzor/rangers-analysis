import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from ida_bytes import get_qword

from rangers_analysis.lib.util import require_name_ea, require_cstr
from rangers_analysis.lib.iterators import require_unique, null_terminated_ptr_array_iterator
from rangers_analysis.lib.funcs import require_function
from rangers_analysis.lib.xrefs import get_code_drefs_to
from rangers_analysis.lib.ua_data_extraction import read_insn, read_source_op_addr_from_reg_assignment
from rangers_analysis.informed_analysis.report import handle_anal_exceptions, print_report, clear_report
from collections import OrderedDict
import json

def is_valid_xref(xref):
    insn = read_insn(xref)
    return insn.mnem == 'lea' and insn.insn.Op1.reg == 1

def get_struct_name(rfl_class_ea):
    rfl_class_cref = require_unique(f"Can't find unique non-getter xref for {rfl_class_ea:x}", [*filter(is_valid_xref, get_code_drefs_to(rfl_class_ea))])

    initializer_func = require_function(rfl_class_cref)
    initializer_func_ea = initializer_func.start_ea

    name = require_cstr(read_source_op_addr_from_reg_assignment(initializer_func_ea, 2))

    return name

def handle_obj_class(objs, obj_class_ea):
    name_ea = get_qword(obj_class_ea)
    name = require_cstr(name_ea)

    spawner_class_ea = get_qword(obj_class_ea + 0x50)

    objs[name] = {} if spawner_class_ea == 0 else { 'struct': get_struct_name(spawner_class_ea) }

clear_report()

obj_class_arr_ea = require_name_ea('?staticGameObjectClasses@GameObjectRegistry@game@hh@@0PAPEAVGameObjectClass@23@A')

objs = OrderedDict()

for rfl_class_ea in null_terminated_ptr_array_iterator(obj_class_arr_ea):
    print(f'top level: handling class {rfl_class_ea:x}')
    handle_anal_exceptions(lambda: handle_obj_class(objs, rfl_class_ea))

f = open(f'rangers-objs.json', 'w')
f.write(json.dumps(objs, indent=2))
f.close()

print_report()
