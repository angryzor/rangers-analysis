from ida_name import get_name, set_name, SN_AUTO
from ida_bytes import get_qword
from ida_ua import o_near, o_mem
from analrangers.lib.ua_data_extraction import read_source_op_addr, read_insn
from analrangers.lib.funcs import ensure_functions
from analrangers.lib.util import require_name_ea
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
        set_name(initializer.start_ea, f'nullinitsub_{f"{ea:x}".upper()}', SN_AUTO)

def find_static_initializers():
    __scrt_common_main_seh_ea = require_name_ea('__scrt_common_main_seh')

    initializer_list_start = read_source_op_addr(__scrt_common_main_seh_ea + 0x75)
    initializer_list_end = read_source_op_addr(__scrt_common_main_seh_ea + 0x6e)

    print(f'info: found static initializer list from {initializer_list_start:x} to {initializer_list_end:x}')

    initializer_list_eas = [get_qword(ea) for ea in range(initializer_list_start, initializer_list_end, 8)]

    for ea in initializer_list_eas:
        if ea != 0:
            handle_anal_exceptions(lambda: handle_static_initializer(ea))
    
    return initializer_list_eas
