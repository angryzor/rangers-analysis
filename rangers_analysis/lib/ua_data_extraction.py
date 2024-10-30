from ida_idaapi import BADADDR
from ida_bytes import is_code, get_full_flags, get_byte, get_word, get_dword, get_qword
from ida_ua import insn_t, decode_insn, decode_prev_insn, print_insn_mnem, o_reg, o_displ, o_mem, o_imm, get_dtype_size
from ida_segment import getseg, get_segm_name
from .iterators import find
from .segments import denuvoized_text_seg
from .analysis_exceptions import AnalysisException
import ctypes

class DecodedInsn:
    def __init__(self, insn, ea, size):
        self.insn = insn
        self.ea = ea
        self.size = size
        self.mnem = print_insn_mnem(ea)
    
    def __str__(self):
        return f'{self.ea:016x} [{self.size:02x}]: {self.mnem}'

def decoded_insns_forward(start_ea, end_ea = None):
    insn_ea = start_ea
    while (is_code(get_full_flags(insn_ea)) or get_byte(insn_ea) == 0x90) and (end_ea == None or insn_ea < end_ea):
        insn = insn_t()
        insn_size = decode_insn(insn, insn_ea)
        if insn_size == 0:
            raise AnalysisException(f"Couldn't decode instruction at {insn_ea:x}")
        yield DecodedInsn(insn, insn_ea, insn_size)
        insn_ea += insn_size

def decoded_insns_backward(start_ea, end_ea = None):
    insn_ea = start_ea
    while insn_ea >= end_ea:
        insn = insn_t()
        prev_insn_ea = decode_prev_insn(insn, insn_ea)
        if prev_insn_ea == BADADDR:
            raise AnalysisException(f"Couldn't decode previous instruction at {insn_ea:x}")
        yield DecodedInsn(insn, prev_insn_ea, insn_ea - prev_insn_ea)
        insn_ea = prev_insn_ea

def find_insn_forward(f, start_ea, end_ea = None):
    return find(f, decoded_insns_forward(start_ea, end_ea))

def find_insn_backward(f, start_ea, end_ea = None):
    return find(f, decoded_insns_backward(start_ea, end_ea))


def read_insn(insn_ea):
    return find_insn_forward(lambda d: True, insn_ea)

def read_source_op_addr(insn_ea):
    return find_insn_forward(lambda d: True, insn_ea).insn.Op2.addr

def read_source_op_addr_from_reg_assignment(start_ea, reg, end_ea = None):
    for d in decoded_insns_forward(start_ea, end_ea):
        if d.mnem == 'lea' and d.insn.Op1.reg == reg:
            return d.insn.Op2.addr
        if d.mnem == 'xor' and d.insn.Op1.reg == reg and d.insn.Op2.reg == reg:
            return 0

def get_denuvo_constant(ea, size):
    match size:
        case 1: return ctypes.c_char(get_byte(ea)).value
        case 2: return ctypes.c_short(get_word(ea)).value
        case 4: return ctypes.c_long(get_dword(ea)).value
        case 8: return ctypes.c_longlong(get_qword(ea)).value
        case _: raise Exception('unexpected datatype') 

def read_source_op_addr_from_mem_assignment_through_single_reg(start_ea, tgt_addr, end_ea = None):
    found_insn = find_insn_forward(lambda d: d.mnem == 'mov' and d.insn.Op1.addr == tgt_addr, start_ea, end_ea)

    for d in decoded_insns_backward(found_insn.ea, start_ea):
        if d.mnem == 'lea' and d.insn.Op1.reg == found_insn.insn.Op2.reg:
            return d.insn.Op2.addr
        if d.mnem == 'xor' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.reg == found_insn.insn.Op2.reg:
            return 0

def read_source_op_imm_from_mem_assignment_through_denuvo_obfuscation(found_insn, start_ea):
    def add_op(value, inner_op): return lambda x: inner_op(x) + value
    def sub_op(value, inner_op): return lambda x: inner_op(x) - value
    def xor_op(value, inner_op): return lambda x: inner_op(x) ^ value

    total_op = lambda x: x

    for d in decoded_insns_backward(found_insn.ea, start_ea):
        if d.mnem == 'add' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_imm:
            total_op = add_op(d.insn.Op2.value, total_op)
            continue
        if d.mnem == 'add' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_mem and get_segm_name(getseg(d.insn.Op2.addr)) == denuvoized_text_seg:
            total_op = add_op(get_denuvo_constant(d.insn.Op2.addr, get_dtype_size(d.insn.Op2.dtype)), total_op)
            continue
        if d.mnem == 'sub' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_imm:
            total_op = sub_op(d.insn.Op2.value, total_op)
            continue
        if d.mnem == 'sub' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_mem and get_segm_name(getseg(d.insn.Op2.addr)) == denuvoized_text_seg:
            total_op = sub_op(get_denuvo_constant(d.insn.Op2.addr, get_dtype_size(d.insn.Op2.dtype)), total_op)
            continue
        if d.mnem == 'xor' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_imm:
            total_op = xor_op(d.insn.Op2.value, total_op)
            continue
        if d.mnem == 'xor' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_mem and get_segm_name(getseg(d.insn.Op2.addr)) == denuvoized_text_seg:
            total_op = xor_op(get_denuvo_constant(d.insn.Op2.addr, get_dtype_size(d.insn.Op2.dtype)), total_op)
            continue
        if d.mnem == 'mov' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_imm:
            return ((1 << (8 * get_dtype_size(found_insn.insn.Op2.dtype))) - 1) & total_op(d.insn.Op2.value)
        if d.mnem == 'mov' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.type == o_mem and get_segm_name(getseg(d.insn.Op2.addr)) == denuvoized_text_seg:
            return ((1 << (8 * get_dtype_size(found_insn.insn.Op2.dtype))) - 1) & total_op(get_denuvo_constant(d.insn.Op2.addr, get_dtype_size(d.insn.Op2.dtype)))
        if d.mnem == 'xor' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.reg == found_insn.insn.Op2.reg:
            return ((1 << (8 * get_dtype_size(found_insn.insn.Op2.dtype))) - 1) & total_op(0)

def read_source_op_imm_from_mem_assignment(start_ea, addr, end_ea = None):
    assignment = find_insn_forward(lambda d: d.mnem == 'mov' and d.insn.Op1.addr == addr, start_ea, end_ea)

    if assignment.insn.Op2.type == o_imm:
        return assignment.insn.Op2.value

    return read_source_op_imm_from_mem_assignment_through_denuvo_obfuscation(assignment, start_ea)

def read_source_op_imm_from_reg_assignment(start_ea, reg, end_ea = None):
    return find_insn_forward(lambda d: d.mnem == 'mov' and d.insn.Op1.reg == reg, start_ea, end_ea).insn.Op2.value

class TrackedValue:
    def __init__(self, data):
        if isinstance(data, TrackedValue):
            self.regs = {*data.regs}
            self.stk_offs = {*data.stk_offs}
        else:
            self.regs = {data}
            self.stk_offs = set()
    
    def __str__(self):
        return f'<regs: {self.regs}, stk_offs: {self.stk_offs}>'

def track_values(values, decoded_insns):
    trackers = { value_name: TrackedValue(values[value_name]) for value_name in values }

    def track_reg(value_name, d):
        tracker = trackers[value_name]

        def is_value_in_source(op):
            if op.type == o_reg: return op.reg in tracker.regs
            if op.type == o_displ: return op.reg == 4 and op.addr in tracker.stk_offs
            return False
        
        def add_dest(op):
            if op.type == o_reg: tracker.regs.add(op.reg)
            if op.type == o_displ and op.reg == 4: tracker.stk_offs.add(op.addr)
        
        def remove_dest(op):
            if op.type == o_reg and op.reg in tracker.regs: tracker.regs.remove(op.reg)
            if op.type == o_displ and op.reg == 4 and op.addr in tracker.stk_offs: tracker.stk_offs.remove(op.addr)

        if d.mnem == 'mov':
            if is_value_in_source(d.insn.Op2):
                # Remove dest if its value is destroyed
                add_dest(d.insn.Op1)
            else:
                # Add dest if the value is copied to it
                remove_dest(d.insn.Op1)
    
    for d in decoded_insns:
        for value_name in trackers.keys():
            track_reg(value_name, d)
        # print(d, d.insn.Op1.is_reg(7), d.insn.Op1.reg, d.insn.Op1.specflag1, d.insn.Op1.specflag2, d.insn.Op1.specflag3, d.insn.Op1.specflag4, d.insn.Op1.specval, d.insn.Op2.value, {str(trackers[k]) for k in trackers})
        yield d, trackers
