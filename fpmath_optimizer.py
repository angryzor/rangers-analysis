from ida_hexrays import minsn_visitor_t, optblock_t, m_fadd, mop_d, mop_r, m_mov, m_low, FD_DEF, minsn_t, mcallinfo_t, mcallarg_t, m_call, mop_f, FCI_SPLOK, FCI_FINAL, FCI_PROP, FCI_NOSIDE
from ida_typeinf import tinfo_t, BTF_FLOAT, CM_CC_FASTCALL
from ida_idaapi import BADADDR
from rangers_analysis.lib.util import require_type

float_type = tinfo_t()
float_type.create_simple_type(BTF_FLOAT)
vec3_type = require_type('csl::math::Vector3')

def generate_vec3_to_float_call(ea, name, *args):
    callinfo = mcallinfo_t(BADADDR, 1)
    callinfo.flags = FCI_SPLOK | FCI_FINAL | FCI_PROP | FCI_NOSIDE
    callinfo.cc = CM_CC_FASTCALL
    callinfo.return_type = float_type

    for arg in args:
        funcarg = mcallarg_t()
        funcarg = arg
        funcarg.type = vec3_type
        funcarg.size = vec3_type.get_size()

        callinfo.args.push_back(funcarg)

    callinsn = minsn_t(ea)
    callinsn.opcode = m_call
    callinsn.l.make_helper(name)
    callinsn.r.zero()
    callinsn.d.t = mop_f
    callinsn.d.f = callinfo
    callinsn.d.size = callinfo.return_type.get_size()

    # movinsn = minsn_t(ea)
    # movinsn.opcode = m_mov
    # movinsn.l.create_from_insn(callinsn)
    # movinsn.r.zero()
    # movinsn.d.t = mop_r
    # movinsn.d.r = 0
    # movinsn.d.size = 8

    return callinsn

def generate_float_to_float_call(ea, name, *args):
    callinfo = mcallinfo_t(BADADDR, 1)
    callinfo.flags = FCI_SPLOK | FCI_FINAL | FCI_PROP | FCI_NOSIDE
    callinfo.cc = CM_CC_FASTCALL
    callinfo.return_type = float_type

    for arg in args:
        funcarg = mcallarg_t()
        funcarg.t = mop_r
        funcarg.r = arg
        funcarg.type = float_type
        funcarg.size = float_type.get_size()

        callinfo.args.push_back(funcarg)

    callinsn = minsn_t(ea)
    callinsn.opcode = m_call
    callinsn.l.make_helper(name)
    callinsn.r.zero()
    callinsn.d.t = mop_f
    callinsn.d.f = callinfo
    callinsn.d.size = callinfo.return_type.get_size()

    # movinsn = minsn_t(ea)
    # movinsn.opcode = m_mov
    # movinsn.l.create_from_insn(callinsn)
    # movinsn.r.zero()
    # movinsn.d.t = mop_r
    # movinsn.d.r = 0
    # movinsn.d.size = 8

    return callinsn

def reduce_mops(mop, opcode):
    if mop.t != mop_d or mop.d.opcode != opcode:
        return [mop]
    else:
        return reduce_ins_mops(mop.d)

def reduce_ins_mops(ins):
    return [*reduce_mops(ins.l, ins.opcode), *reduce_mops(ins.r, ins.opcode)]

# and ins.d.t == mop_r and ins.d.r == ret 
def is_helper_call(ins, f, *args):
    return (ins.opcode == m_mov or ins.opcode == m_low) and ins.l.t == mop_d and f(ins.l.d, *args)

def is_mul(ins): return ins.is_helper('_mm_mul_ps')
def is_shuffle(ins): return ins.is_helper('_mm_shuffle_ps')
def is_sqrt(ins): return ins.is_helper('_mm_sqrt_ps')

def is_mul_with(ins, r1, r2):
    print(f'checking mul on {ins.dstr()}, r1 {r1}, r2 {r2}')
    print(f'real = f `{ins.l.helper}`, r1 {ins.d.f.args[0].r}, r2 {ins.d.f.args[1].r}')
    return is_mul(ins) and ins.d.f.args[0].r == r1 and ins.d.f.args[1].r == r2

def is_shuffle_with(ins, r1, r2, control):
    print(f'checking shuffle on {ins.dstr()}, r1 {r1}, r2 {r2}, ctrl {control}')
    print(f'real = f `{ins.l.helper}`, r1 {ins.d.f.args[0].r}, r2 {ins.d.f.args[1].r}, ctrl {ins.d.f.args[2].nnn.value}')
    return is_shuffle(ins) and ins.d.f.args[0].r == r1 and ins.d.f.args[1].r == r2 and ins.d.f.args[2].nnn.value == control

def one_each(mops, preds):
    if len(mops) != len(preds):
        return False
    
    leftover_preds = set(preds)

    for mop in mops:
        count = 0
        matching_pred = None
        for pred in leftover_preds:
            if pred(mop):
                count += 1
                matching_pred = pred
        if count != 1:
            return False
        leftover_preds.remove(matching_pred)
    
    return True

def search_back(startins, f):
    curins = startins.prev

    while curins != None:
        if f(curins):
            return curins
        curins = curins.prev

def find_reg_def(startins, reg):
    return search_back(startins, lambda ins: ins.d.t == mop_r and ins.d.r == reg)

def select_x_from_float(ins, top, blk):
    if not is_helper_call(ins, is_shuffle): return False
    
    print('possible candidate for select_x_from_float')
    first_r = ins.l.d.d.f.args[0].r
    print(f'first_r: {first_r}')
    
    if not is_helper_call(ins, is_shuffle_with, first_r, first_r, 0): return False
    
    reg_def = find_reg_def(ins, first_r)

    if reg_def == None or reg_def.d.size != 4: return False

    ins.opcode = m_mov
    ins.l.erase()
    ins.l.t = mop_r
    ins.l.r = first_r
    ins.l.size = 4
    ins.r.zero()
    ins.d.size = 4

    return True

def sqrt_on_float(ins, top, blk):
    if not is_helper_call(ins, is_sqrt): return False
    
    print('possible candidate for sqrt_on_float')
    r = ins.l.d.d.f.args[0].r
    print(f'r: {r}')
    
    reg_def = find_reg_def(ins, r)

    if reg_def == None or reg_def.d.size != 4: return False

    callins = generate_float_to_float_call(ins.ea, "sqrt", r)

    ins.opcode = m_mov
    ins.l.erase()
    ins.l.create_from_insn(callins)
    ins.l.size = 4
    ins.r.zero()
    ins.d.size = 4

    return True

def dot_product(ins, top, blk):
    if ins.opcode != m_fadd: return False
    
    mops = reduce_ins_mops(ins)

    for mop in mops:
        print(f'=> mop {mop.dstr()}, mop type {mop.t} - {mop.t == mop_d} - {mop.d}')

    if len(mops) != 3: return False

    print('possible candidate for dot_product')

    for mop in mops:
        if mop.t != mop_r:
            return False
    print('all mops are registers')

    mop2_access = find_reg_def(top, mops[2].r)

    if mop2_access == None: print('no mop2 found'); return False

    mop1_access = find_reg_def(mop2_access, mops[1].r)

    if mop1_access == None: print('no mop1 found'); return False

    mop0_access = find_reg_def(mop1_access, mops[0].r)

    if mop0_access == None: print('no mop0 found'); return False

    print(mop0_access)
    print(mop1_access)
    print(mop2_access)

    if not is_helper_call(mop2_access, is_shuffle_with, mops[1].r, mops[1].r, 0x55): print('nomop2'); return False
    if not is_helper_call(mop1_access, is_shuffle_with, mops[0].r, mops[0].r, 0x99): print('nomop1'); return False
    if not is_helper_call(mop0_access, is_mul) and mop0_access.l.d.d.f.args[0].equal_mops(mop0_access.l.d.d.f.args[1]) : print('nomop0'); return False

    callins = generate_vec3_to_float_call(ins.ea, "vec3_norm", mop0_access.l.d.d.f.args[0])

    ins.opcode = m_mov
    ins.l.erase()
    ins.l.create_from_insn(callins)
    ins.l.size = 4
    ins.r.zero()

    blk.remove_from_block(mop0_access)
    blk.remove_from_block(mop1_access)
    blk.remove_from_block(mop2_access)

    return True

filters = [select_x_from_float, sqrt_on_float, dot_product]

class subinsn_optimizer_t(minsn_visitor_t):
    cnt = 0

    def __init__(self, curblock):
        super().__init__()
        self.curblock = curblock

    def visit_minsn(self):
        ins = self.curins

        print(ins.dstr())

        for f in filters:
            if f(ins, self.topins, self.curblock):
                self.cnt += 1

        return 0


class FPMathOptimizer(optblock_t):
    def func(self, blk):
        print('----- begin -----')
        opt = subinsn_optimizer_t(blk)
        blk.for_all_insns(opt)
        if opt.cnt != 0:
            blk.mark_lists_dirty()
            blk.mba.verify(True)
        print('----- end -----')
        return opt.cnt

# class fpmath_optimizer_plugin_t(ida_idaapi.plugin_t):
#     flags = ida_idaapi.PLUGIN_HIDE
#     wanted_name = "Floating point math optimizer"
#     wanted_hotkey = ""
#     comment = ""
#     help = ""
#     def init(self):
#         if ida_hexrays.init_hexrays_plugin():
#             self.optimizer = FPMathOptimizer()
#             self.optimizer.install()
#             print("Floating point math optimizer installed")
#             return ida_idaapi.PLUGIN_KEEP
#     def term(self):
#         self.optimizer.remove()
#     def run(self, arg):
#         if arg == 1:
#             return self.optimizer.remove()
#         elif arg == 2:
#             return self.optimizer.install()

# def PLUGIN_ENTRY():
#     return fpmath_optimizer_plugin_t()
try:
    fpmathopt
    try:
        fpmathopt.remove()
        del fpmathopt
        print('fpmathopt unregistered')
    except Exception as err:
        print(str(err))
except:
    fpmathopt = FPMathOptimizer()
    fpmathopt.install()
    print('fpmathopt installed')