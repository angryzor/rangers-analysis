from ida_segment import getseg, get_segm_name
from ida_bytes import get_qword, is_strlit, get_flags
from ida_typeinf import idc_guess_type
from ida_name import set_name
from analrangers.lib.util import require_type, require_name_ea, force_apply_tinfo, class_name_to_backrefs
from analrangers.lib.heuristics import get_best_class_name, guess_instantiator_from_constructor, guess_subclass_constructors_from_constructor, get_getter_xref
from analrangers.lib.funcs import set_func_name, require_function, require_thunk, ensure_functions
from analrangers.lib.naming import set_generated_vtable_name_through_ctor
from analrangers.lib.xrefs import get_drefs_to, get_crefs_to
from analrangers.lib.iterators import UniqueNotFoundException
from .report import handle_anal_exceptions

class_tif = require_type('hh::game::GOComponentClass')

def find_goc_class(instantiator_thunk):
    goc_class_eas = []

    for dref in get_drefs_to(instantiator_thunk.start_ea):
        if get_segm_name(getseg(dref)) != '.rodata':
            continue

        if get_qword(dref) != instantiator_thunk.start_ea:
            # We found something, but the data is not undefined and the xref is in the tail. Try to find out if this is already a GOComponentClass.
            if 'GOComponentClass' in idc_guess_type(dref):
                goc_class_eas.append(dref)
            else:
                print(f'warn: GOC constructor xref {dref:x} is not a hh::game::GOComponentClass, ignoring')

            continue


        class_ea = dref - 0x28
        class_name_ea = get_qword(class_ea)

        if not is_strlit(get_flags(class_name_ea)):
            print(f'warn: {class_ea:x} does not look like a hh::game::GOComponentClass, ignoring')
            continue

        goc_class_eas.append(class_ea)
    
    if len(goc_class_eas) == 1:
        return goc_class_eas[0]

def handle_goc_ctor(ctor_func):
    ctor_thunk = require_thunk(ctor_func)
    
    try:
        instantiator_func = guess_instantiator_from_constructor(ctor_func)
        instantiator_thunk = require_thunk(instantiator_func)
        class_ea = find_goc_class(instantiator_thunk)
    except UniqueNotFoundException:
        instantiator_func = None
        instantiator_thunk = None
        class_ea = None
        print(f'info: {ctor_func.start_ea:x} may be a superclass, trying to analyze subclasses')
        analyze_direct_goc_ctor_subclasses(ctor_func)

    if class_ea != None:
        force_apply_tinfo(class_ea, class_tif)

    class_name, using_fallback_name = get_best_class_name(ctor_func, class_ea and get_qword(class_ea), 'gocs')

    print(f'info: handling GOC at {ctor_func.start_ea:x}: {class_name}')

    if instantiator_thunk != None:
        set_func_name(instantiator_thunk, f'?Instantiate@{class_name}@@CAPEAV{class_name_to_backrefs(class_name)}@PEAVIAllocator@fnd@csl@@@Z')
    if ctor_func != instantiator_func:
        set_func_name(ctor_thunk, f'??0{class_name}@@AEAA@PEAVIAllocator@fnd@csl@@@Z')

    if class_ea == None:
        print(f'warn: Could not find a reliable hh::game::GOComponentClass xref for constructor {ctor_thunk.start_ea:x} (instantiator thunk was {instantiator_thunk.start_ea if instantiator_thunk else 0:x}). Constructor name has been deduced through vtable.')
        return

    set_name(get_qword(class_ea + 8), f'?classId@{class_name}@@0PEBXEB')
    set_name(class_ea, f'?staticClass@{class_name}@@0PEAVGOComponentClass@game@hh@@EA')

    getter_ea = get_getter_xref(class_ea)
    if getter_ea != None:
        set_func_name(ensure_functions(getter_ea), f'?GetClass@{class_name}@@CAPEAVGOComponentClass@game@hh@@XZ')
    else:
        print(f'warn: no GetClass function found for GOComponent class at {class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(ctor_func, class_name)

def analyze_direct_goc_ctor_subclasses(ctor):
    for subctor in guess_subclass_constructors_from_constructor(ctor):
        handle_anal_exceptions(lambda: handle_goc_ctor(subctor))
    
def find_gocs():
    base_ctor_ea = require_name_ea('??0GOComponent@game@hh@@QEAA@PEAVIAllocator@fnd@csl@@@Z')
    base_ctor = require_function(base_ctor_ea)

    analyze_direct_goc_ctor_subclasses(base_ctor)
