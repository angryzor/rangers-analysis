from ida_segment import getseg, get_segm_name
from ida_bytes import get_qword, is_strlit, get_flags
from ida_typeinf import idc_guess_type
from analrangers.lib.util import require_type, require_name_ea, force_apply_tinfo
from analrangers.lib.heuristics import get_best_class_name, discover_class_hierarchy, get_getter_xref
from analrangers.lib.funcs import require_function, ensure_functions
from analrangers.lib.naming import set_generated_vtable_name_through_ctor, set_generated_name, create_name, set_private_instantiator_func_name, set_simple_constructor_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType, friendly_class_name
from analrangers.lib.xrefs import get_drefs_to
from analrangers.lib.segments import data_seg
from .report import handle_anal_exceptions

class_tif = require_type('hh::game::GOComponentClass')

class_class_name = ['GOComponentClass', 'game', 'hh']

def find_goc_class(instantiator_thunk):
    goc_class_eas = []

    for dref in get_drefs_to(instantiator_thunk.start_ea):
        if get_segm_name(getseg(dref)) != data_seg:
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

def handle_goc_ctor(instantiator_thunk, instantiator_func, ctor_thunk, ctor_func, base_ctor_func):
    class_ea = instantiator_thunk and find_goc_class(instantiator_thunk)

    class_name, using_fallback_name = get_best_class_name(ctor_func, class_ea and get_qword(class_ea), 'gocs')

    print(f'info: handling GOC at {ctor_func.start_ea:x}: {friendly_class_name(class_name)}')

    if instantiator_thunk != None:
        set_private_instantiator_func_name(instantiator_thunk, class_name)
    if ctor_func != instantiator_func:
        set_simple_constructor_func_name(ctor_thunk, class_name)

    if class_ea == None:
        print(f'warn: Could not find a reliable hh::game::GOComponentClass xref for constructor {ctor_thunk.start_ea:x} (instantiator thunk was {instantiator_thunk.start_ea if instantiator_thunk else 0:x}). Constructor name has been deduced through vtable.')
        return
    
    force_apply_tinfo(class_ea, class_tif)

    class_var = StaticObjectVar('componentClass', class_class_name, StaticObjectVarType.VAR, True)

    set_generated_name(get_qword(class_ea + 8), create_name('?{0}@0PEBXEB', ['classId', *class_name]))
    set_static_var_name(class_ea, class_name, class_var)

    getter_ea = get_getter_xref(class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetClass')
    else:
        print(f'warn: no GetClass function found for GOComponent class at {class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(ctor_func, class_name)

def find_gocs():
    base_ctor_ea = require_name_ea('??0GOComponent@game@hh@@QEAA@PEAVIAllocator@fnd@csl@@@Z')
    base_ctor = require_function(base_ctor_ea)

    for funcs in discover_class_hierarchy(base_ctor):
        handle_anal_exceptions(lambda: handle_goc_ctor(*funcs))
