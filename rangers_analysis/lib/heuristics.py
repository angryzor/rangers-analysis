import re
from ida_name import get_name
from ida_segment import get_segm_name, getseg
from ida_ua import print_insn_mnem, o_phrase, o_displ, o_reg, o_mem, o_near, o_imm
from ida_bytes import get_qword, get_flags, is_code, has_user_name, is_strlit
from ida_idaapi import BADADDR
from ida_funcs import get_func, get_fchunk
from ida_idp import reg_accesses_t, ph_get_reg_accesses
from ida_typeinf import idc_guess_type
from .util import get_cstr
from .ua_data_extraction import find_insn_forward, read_insn, decoded_insns_forward, track_values
from .xrefs import get_drefs_to, get_safe_crefs_to, get_code_drefs_to
from .analysis_exceptions import AnalysisException
from .require import require_wrap, NotFoundException
from .funcs import require_function, require_thunk, ensure_functions, find_implementation, FunctionNotFoundException
from .iterators import require_unique, find, UniqueNotFoundException
from .segments import rdata_seg, data_seg

def guess_vtable_from_constructor(f):
    # Our little tracing asm walker can't deal with multi-chunk functions, so just take the first chunk so it doesn't crash
    f = get_fchunk(f.start_ea)

    last_ea = f.start_ea
    values = {}
    found_vtable_load = None

    while vtable_load := find(
        lambda i: i[0].mnem == 'lea' and i[0].insn.Op2.type == o_mem and not is_code(get_flags(i[0].insn.Op2.addr)) and get_segm_name(getseg(i[0].insn.Op2.addr)) == rdata_seg,
        track_values(values, decoded_insns_forward(last_ea, f.end_ea))
    ):
        last_ea = vtable_load[0].ea + vtable_load[0].size
        values = vtable_load[1]

        assignment = find(
            lambda i: i[0].mnem == 'mov' and i[0].insn.Op1.type == o_phrase and ('this' not in i[1] or i[0].insn.Op1.reg in i[1]['this'].regs) and i[0].insn.Op2.type == o_reg and i[0].insn.Op2.reg in i[1]['vtbl'].regs,
            track_values({ **values, 'vtbl': vtable_load[0].insn.Op1.reg }, decoded_insns_forward(last_ea, f.end_ea))
        )
        if not assignment:
            if not found_vtable_load:
                print(f"warn: found {vtable_load[0].ea:x} as potential vtable assignment, but it doesn't look correct. ignoring.")
            continue

        if found_vtable_load:
            print(f"warn: previously found {found_vtable_load.ea:x} as potential vtable assignment, but now found another one for the same target at {vtable_load[0].ea:x}. Assuming the first one was an inline base constructor and taking the last one.")

        last_ea = assignment[0].ea + assignment[0].size
        values = { 'this': assignment[1]['this'] if 'this' in assignment[1] else assignment[0].insn.Op1.reg }

        found_vtable_load = vtable_load[0]

    return found_vtable_load and found_vtable_load.insn.Op2.addr

class VTableNotFoundException(NotFoundException):
    def __init__(self, ctor_func):
        super().__init__(f'Could not find vtable for constructor {ctor_func.start_ea:x}')

require_vtable = require_wrap(VTableNotFoundException, guess_vtable_from_constructor)

def follow_jmp_chains_to_next_func(insn_ea):
    f = require_function(insn_ea)
    insn = read_insn(insn_ea)
    while f.start_ea != insn_ea:
        if insn.mnem != 'jmp':
            return None

        insn_ea = insn.insn.Op1.addr
        f = require_function(insn_ea)
        insn = read_insn(insn_ea)
    return f

def looks_like_constructor(f):
    return guess_vtable_from_constructor(f)

def guess_constructor_thunk_from_instantiator(f):
    if looks_like_constructor(f):
        return f
    
    if jmp_insn := find_insn_forward(lambda d: d.mnem == 'jmp' and d.insn.Op1.type == o_near, f.start_ea, f.end_ea):
        if ctor := follow_jmp_chains_to_next_func(jmp_insn.ea):
            return ctor

class ConstructorNotFoundException(NotFoundException):
    def __init__(self, f):
        super().__init__(f"Can't find constructor from instantiator {f.start_ea:x}")

require_constructor_thunk_from_instantiator = require_wrap(VTableNotFoundException, guess_constructor_thunk_from_instantiator)

def looks_like_instantiator(f):
    # Our little tracing asm walker can't deal with multi-chunk functions, so just take the first chunk so it doesn't crash
    f = get_fchunk(f.start_ea)

    # Check if we try to read out the vtable of rcx, presumably the allocator.
    vtbl_res = find(
        lambda i: i[0].mnem == 'mov' and i[0].insn.Op1.type == o_reg and i[0].insn.Op2.type == o_phrase and i[0].insn.Op2.reg in i[1]['allocator'].regs,
        track_values({ 'allocator': 1 }, decoded_insns_forward(f.start_ea, f.end_ea))
    )
    if not vtbl_res: return False
    vtbl_insn, at_vtbl_insn_values = vtbl_res
    after_vtbl_insn_values = { **at_vtbl_insn_values, 'alloc_vtable': vtbl_insn.insn.Op1.reg }

    # See if we do a direct call on a displacement operand
    displ_call_res = find(
        lambda i: i[0].mnem == 'call' and i[0].insn.Op1.type == o_displ and i[0].insn.Op1.addr == 8 and i[0].insn.Op1.reg in i[1]['alloc_vtable'].regs and 1 in i[1]['allocator'].regs,
        track_values(after_vtbl_insn_values, decoded_insns_forward(vtbl_insn.ea + vtbl_insn.size, f.end_ea))
    )
    if displ_call_res: return True

    # Otherwise, see if we first read out the function pointer separately and then do a call on a register
    allocfn_res = find(
        lambda i: i[0].mnem == 'mov' and i[0].insn.Op1.type == o_reg and i[0].insn.Op2.type == o_displ and i[0].insn.Op2.addr == 8 and i[0].insn.Op2.reg in i[1]['alloc_vtable'].regs,
        track_values(after_vtbl_insn_values, decoded_insns_forward(vtbl_insn.ea + vtbl_insn.size, f.end_ea))
    )
    if not allocfn_res: return False
    allocfn_insn, at_allocfn_insn_values = allocfn_res
    after_allocfn_insn_values = { **at_allocfn_insn_values, 'allocfn': allocfn_insn.insn.Op1.reg }

    call_res = find(
        lambda i: i[0].mnem == 'call' and i[0].insn.Op1.type == o_reg and i[0].insn.Op1.reg in i[1]['allocfn'].regs and 1 in i[1]['allocator'].regs,
        track_values(after_allocfn_insn_values, decoded_insns_forward(allocfn_insn.ea + allocfn_insn.size, f.end_ea))
    )
    if call_res: return True

    return False


    # # Find first assignment of rax
    # alloc_assign = find_insn_forward(lambda d: d.mnem == 'mov' and d.insn.Op1.type == o_reg and d.insn.Op1.reg == 0 and d.insn.Op2.type == o_phrase and d.insn.Op2.reg == 1, f.start_ea, f.end_ea)
    # if not alloc_assign: return False

    # # Find first call
    # call = find_insn_forward(lambda d: d.mnem == 'call' and d.insn.Op1.type == o_displ and d.insn.Op1.reg == 0, alloc_assign.ea + alloc_assign.size, f.end_ea)
    # if not call: return False

    # # Make sure rcx is not reassigned between func start and call
    # if find_insn_forward(lambda d: (d.mnem == 'mov' or d.mnem == 'lea') and d.insn.Op1.type == o_reg and d.insn.Op1.reg == 1, f.start_ea, call.ea): return False

    # # Make sure rax is not reassigned between assignment and call
    # if find_insn_forward(lambda d: (d.mnem == 'mov' or d.mnem == 'lea') and d.insn.Op1.type == o_reg and d.insn.Op1.reg == 0, alloc_assign.ea + alloc_assign.size, call.ea): return False

    # return True

def guess_instantiator_from_constructor(f):
    if looks_like_instantiator(f):
        return f

    ctor_thunk = require_thunk(f)
    ctor_crefs = filter(lambda i: i and looks_like_instantiator(i) and not looks_like_constructor(i), map(get_func, get_safe_crefs_to(ctor_thunk.start_ea)))

    return require_unique(f"Couldn't find unique instantiator xref for constructor {f.start_ea:x}. Constructor may be constructor of an abstract superclass.", ctor_crefs)

def guess_subclass_constructors_from_constructor(f):
    # TODO: handle refs to all intermediary thunks
    ctor_thunk = require_thunk(f)
    for cref in get_safe_crefs_to(ctor_thunk.start_ea):
        try:
            subf = require_function(cref)
            if looks_like_constructor(subf): 
                yield subf
        except FunctionNotFoundException:
            print(f'warn: ignoring {cref:x} in subconstructor search as it is not a function')
        except AnalysisException as e:
            print(f'warn: could not try {cref:x} due to analysis exception: {e}')

def estimate_class_name_from_vtable_name(name):
    m = re.match(r'^\?\?_7(.+)@@6B@$', name)
    if m:
        return m.group(1).split('@')

def estimate_class_name_from_vtable(ea):
    name = get_name(ea)
    if name == None:
        return None

    return estimate_class_name_from_vtable_name(name)

def estimate_class_name_from_constructor(f):
    vtable_ea = guess_vtable_from_constructor(f)
    if vtable_ea != None and (is_rtti_identified_vtable(vtable_ea) or has_user_name(get_flags(vtable_ea))):
        return estimate_class_name_from_vtable(vtable_ea)

class ClassNameNotFoundException(NotFoundException):
    def __init__(self, ctor_func):
        super().__init__(f'Could not find vtable-based class name for constructor {ctor_func.start_ea:x}')

require_class_name_from_constructor = require_wrap(ClassNameNotFoundException, estimate_class_name_from_constructor)

def is_deleting_destructor(dtor):
    def is_test_insn(i):
        if not i[0].mnem == 'test' or not i[0].insn.Op1.type == o_reg: return False

        accesses = reg_accesses_t()
        ph_get_reg_accesses(accesses, i[0].insn, 0)

        return i[0].insn.Op2.type == o_imm and i[0].insn.Op2.value == 1 and accesses[0].regnum in i[1]['flags'].regs

    return find(is_test_insn, track_values({ 'flags': 2 }, decoded_insns_forward(dtor.start_ea, dtor.end_ea)))

def guess_vbase_destructor_thunk_from_deleting_destructor(dtor):
    if call_insn := find_insn_forward(lambda i: i.mnem == 'call', dtor.start_ea, dtor.end_ea):
        if call_insn.insn.Op1.type == o_near:
            return require_function(call_insn.insn.Op1.addr)

class VBaseDtorNotFoundException(NotFoundException):
    def __init__(self, dtor_func):
        super().__init__(f'Could not find vbase destructor for deleting destructor {dtor_func.start_ea:x}')

require_vbase_destructor_from_deleting_destructor = require_wrap(VBaseDtorNotFoundException, estimate_class_name_from_constructor)

def guess_constructor_from_vtable(vtable_ea):
    dtor_thunk = ensure_functions(get_qword(vtable_ea))
    dtor = find_implementation(dtor_thunk)
    
    if is_deleting_destructor(dtor):
        base_dtor_thunk = guess_vbase_destructor_thunk_from_deleting_destructor(dtor)
        base_dtor = base_dtor_thunk and find_implementation(base_dtor_thunk)
    else:
        base_dtor_thunk, base_dtor = None, None

    ctor_xrefs = filter(lambda i: i and i.start_ea != dtor.start_ea and (not base_dtor or i.start_ea != base_dtor.start_ea) and looks_like_constructor(i) and guess_vtable_from_constructor(i) == vtable_ea, map(get_func, get_code_drefs_to(vtable_ea)))

    return require_unique(f"Could't find unique constructor for vtable {vtable_ea:x}", ctor_xrefs)

def is_rtti_identified_vtable(ea):
    existing_name = get_name(ea)
    
    if existing_name == None or not existing_name.startswith('??_7'):
        return False
    
    col_ea = get_qword(ea - 8)

    return get_qword(col_ea) != BADADDR and get_name(col_ea) == '??_R4' + existing_name[4:]

def generated_class_name(name, category, prefix = 'heur'):
    return [name, category, prefix]

def get_best_class_name(ctor_func, short_name_ea, category):
    class_name = ctor_func and estimate_class_name_from_constructor(ctor_func)
    if class_name != None:
        return class_name, False
    
    if short_name_ea == None:
        raise AnalysisException(f'Could not find a reliable short nor a vtable-based class name for constructor {ctor_func.start_ea:x}. No naming source available.')

    name = get_cstr(short_name_ea)
    if name == None:
        raise AnalysisException(f'No vtable-based class name available for constructor {ctor_func.start_ea:x}, and no short name found at {short_name_ea:x}. No naming source available.')

    return generated_class_name(name, category), True

def get_getter_xref(ea):
    for xref in get_drefs_to(ea):
        if is_code(get_flags(xref)) and print_insn_mnem(xref) == 'lea' and print_insn_mnem(xref + 7) == 'retn':
            return xref

def find_instantiator_from_constructor(ctor_func):
    ctor_thunk = require_thunk(ctor_func)

    try:
        instantiator_func = guess_instantiator_from_constructor(ctor_func)
        instantiator_thunk = require_thunk(instantiator_func)
    except UniqueNotFoundException:
        instantiator_func = None
        instantiator_thunk = None
        print(f'info: No instantiator found for {ctor_func.start_ea:x}. It may be an abstract superclass.')

    return instantiator_thunk, instantiator_func, ctor_thunk

def find_class_object(class_name, segment, xref_offset, instantiator_thunk):
    class_eas = []

    for dref in get_drefs_to(instantiator_thunk.start_ea):
        if get_segm_name(getseg(dref)) != segment:
            continue

        if get_qword(dref) != instantiator_thunk.start_ea:
            # We found something, but the data is not undefined and the xref is in the tail. Try to find out if this is already a ManagedResourceClass.
            if class_name in idc_guess_type(dref):
                class_eas.append(dref)
            else:
                print(f'warn: resource constructor xref {dref:x} is not a {class_name}, ignoring')

            continue

        class_ea = dref - xref_offset
        class_name_ea = get_qword(class_ea)

        if not is_strlit(get_flags(class_name_ea)):
            print(f'warn: {class_ea:x} does not look like a {class_name}, ignoring')
            continue

        class_eas.append(class_ea)
    
    if len(class_eas) == 1:
        return class_eas[0]

# Attempts to find all classes of a class hierarchy.
def discover_class_hierarchy(base_ctor):
    for ctor_func in guess_subclass_constructors_from_constructor(base_ctor):
        instantiator_and_ctor_thunk = find_instantiator_from_constructor(ctor_func)

        yield *instantiator_and_ctor_thunk, ctor_func, base_ctor

        yield from discover_class_hierarchy(ctor_func)
