from ida_name import get_name
from ida_bytes import get_qword
from ida_ua import o_near, o_mem
from rangers_analysis.lib.ua_data_extraction import read_source_op_addr, read_insn
from rangers_analysis.lib.funcs import ensure_functions
from rangers_analysis.lib.util import require_name_ea
from rangers_analysis.lib.naming import set_generated_name
from .report import handle_anal_exceptions

atexit_ea = require_name_ea('atexit')

def is_null_initializer(f):
    insn = read_insn(f.start_ea)
    if not insn or insn.mnem != 'lea' or insn.insn.Op1.reg != 1 or insn.insn.Op2.type != o_mem or not get_name(insn.insn.Op2.addr).startswith('nullsub_'): return False
    
    insn = read_insn(insn.ea + insn.size)
    if not insn or insn.mnem != 'jmp' or insn.insn.Op1.type != o_near or insn.insn.Op1.addr != atexit_ea: return False

    return True


def handle_static_initializer(ea):
    initializer = ensure_functions(ea)

    if is_null_initializer(initializer):
        set_generated_name(initializer.start_ea, f'nullinitsub_{f"{ea:x}".upper()}')

def find_static_initializers():
    initializer_list_start = require_name_ea('staticInitializersStart')
    initializer_list_end = require_name_ea('staticInitializersEnd')

    print(f'info: found static initializer list from {initializer_list_start:x} to {initializer_list_end:x}')

    initializer_list_eas = [get_qword(ea) for ea in range(initializer_list_start, initializer_list_end, 8)]

    for ea in initializer_list_eas:
        if ea != 0:
            handle_anal_exceptions(lambda: handle_static_initializer(ea))
    
    return initializer_list_eas
