from ida_idaapi import BADADDR
from ida_ua import insn_t, decode_insn, decode_prev_insn, print_insn_mnem, o_reg, o_displ
from .iterators import find

class DecodedInsn:
    def __init__(self, insn, ea, size):
        self.insn = insn
        self.ea = ea
        self.size = size
        self.mnem = print_insn_mnem(ea)

def decoded_insns_forward(start_ea, end_ea = None):
    insn_ea = start_ea
    while end_ea == None or insn_ea < end_ea:
        insn = insn_t()
        insn_size = decode_insn(insn, insn_ea)
        yield DecodedInsn(insn, insn_ea, insn_size)
        insn_ea += insn_size

def decoded_insns_backward(start_ea, end_ea = None):
    insn_ea = start_ea
    while insn_ea >= end_ea:
        insn = insn_t()
        prev_insn_ea = decode_prev_insn(insn, insn_ea)
        if prev_insn_ea == BADADDR:
            break
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
    return find_insn_forward(lambda d: d.mnem == 'lea' and d.insn.Op1.reg == reg, start_ea, end_ea).insn.Op2.addr

def read_source_op_addr_from_mem_assignment_through_single_reg(start_ea, tgt_addr, end_ea = None):
    found_insn = find_insn_forward(lambda d: d.mnem == 'mov' and d.insn.Op1.addr == tgt_addr, start_ea, end_ea)

    for d in decoded_insns_backward(found_insn.ea, start_ea):
        if d.mnem == 'lea' and d.insn.Op1.reg == found_insn.insn.Op2.reg:
            return d.insn.Op2.addr
        if d.mnem == 'xor' and d.insn.Op1.reg == found_insn.insn.Op2.reg and d.insn.Op2.reg == found_insn.insn.Op2.reg:
            return 0

def read_source_op_imm_from_mem_assignment(start_ea, addr, end_ea = None):
    return find_insn_forward(lambda d: d.mnem == 'mov' and d.insn.Op1.addr == addr, start_ea, end_ea).insn.Op2.value

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
        yield d, trackers
