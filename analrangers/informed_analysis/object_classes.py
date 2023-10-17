from ida_bytes import get_qword, get_dword, get_flags, is_strlit
from ida_typeinf import tinfo_t, idc_guess_type
from ida_segment import getseg, get_segm_name
from analrangers.lib.funcs import ensure_functions, find_implementation, require_function
from analrangers.lib.heuristics import get_best_class_name, require_constructor_thunk_from_instantiator, discover_class_hierarchy, get_getter_xref
from analrangers.lib.util import get_cstr, require_type, force_apply_tinfo, force_apply_tinfo_array, require_name_ea
from analrangers.lib.naming import set_generated_vtable_name_through_ctor, set_private_instantiator_func_name, set_simple_constructor_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVarType, StaticObjectVar, friendly_class_name
from analrangers.lib.ua_data_extraction import read_source_op_addr
from analrangers.lib.iterators import null_terminated_ptr_array_iterator
from analrangers.lib.xrefs import get_drefs_to
from analrangers.lib.segments import data_seg
from .report import handle_anal_exceptions

obj_class_tif = require_type('hh::game::GameObjectClass')
rfl_member_value_tif = require_type('hh::fnd::RflClassMember::Value')

class_class_name = ['GameObjectClass', 'game', 'hh']
rflclass_member_value_class_name = ['Value', 'RflClassMember', 'fnd', 'hh']

# High confidence analysis for objects in the registry
def handle_obj_class(obj_class_ea):
    name_ea = get_qword(obj_class_ea)
    instantiator_thunk_ea = get_qword(obj_class_ea + 0x20)

    print(f'info: handling ObjectClass at {obj_class_ea:x}: {get_cstr(name_ea)}')

    force_apply_tinfo(obj_class_ea, obj_class_tif)

    instantiator_thunk = ensure_functions(instantiator_thunk_ea)
    instantiator = find_implementation(instantiator_thunk)
    constructor_thunk = require_constructor_thunk_from_instantiator(instantiator)
    constructor = find_implementation(constructor_thunk)

    class_name, using_fallback_name = get_best_class_name(constructor, name_ea, 'gameobjects')

    member_value_count = get_dword(obj_class_ea + 0x40)
    member_value_array_ea = get_qword(obj_class_ea + 0x48)

    if member_value_count != 0 and member_value_array_ea != 0:
        force_apply_tinfo_array(member_value_array_ea, rfl_member_value_tif, member_value_count)

    class_members_var = StaticObjectVar('gameObjectClassMembers', rflclass_member_value_class_name, StaticObjectVarType.ARRAY, True)
    class_var = StaticObjectVar('gameObjectClass', class_class_name, StaticObjectVarType.VAR, True)

    set_static_var_name(member_value_array_ea, class_name, class_members_var)
    set_static_var_name(obj_class_ea, class_name, class_var)

    set_private_instantiator_func_name(instantiator_thunk, class_name)
    if instantiator != constructor_thunk:
        set_simple_constructor_func_name(constructor_thunk, class_name)

    getter_ea = get_getter_xref(obj_class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetClass')
    else:
        print(f'warn: no GetClass function found for GameObject class at {obj_class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(constructor, class_name)

def find_obj_class(instantiator_thunk):
    obj_class_eas = []

    for dref in get_drefs_to(instantiator_thunk.start_ea):
        if get_segm_name(getseg(dref)) != data_seg:
            continue

        if get_qword(dref) != instantiator_thunk.start_ea:
            # We found something, but the data is not undefined and the xref is in the tail. Try to find out if this is already a GameObjectClass.
            if 'GameObjectClass' in idc_guess_type(dref):
                obj_class_eas.append(dref)
            else:
                print(f'warn: obj constructor xref {dref:x} is not a hh::game::GameObjectClass, ignoring')

            continue


        class_ea = dref - 0x20
        class_name_ea = get_qword(class_ea)

        if not is_strlit(get_flags(class_name_ea)):
            print(f'warn: {class_ea:x} does not look like a hh::game::GameObjectClass, ignoring')
            continue

        obj_class_eas.append(class_ea)
    
    if len(obj_class_eas) == 1:
        return obj_class_eas[0]

# Lower confidence analysis for subclasses of GameObject
def handle_obj_ctor(instantiator_thunk, instantiator_func, ctor_thunk, ctor_func, base_ctor_func):
    class_ea = instantiator_thunk and find_obj_class(instantiator_thunk)

    class_name, using_fallback_name = get_best_class_name(ctor_func, class_ea and get_qword(class_ea), 'gameobjects')

    print(f'info: handling GameObject at {ctor_func.start_ea:x}: {friendly_class_name(class_name)}')

    if instantiator_thunk != None:
        set_private_instantiator_func_name(instantiator_thunk, class_name)
    if ctor_func != instantiator_func:
        set_simple_constructor_func_name(ctor_thunk, class_name)

    if class_ea == None:
        print(f'warn: Could not find a reliable hh::game::GameObjectClass xref for constructor {ctor_thunk.start_ea:x} (instantiator thunk was {instantiator_thunk.start_ea if instantiator_thunk else 0:x}). Constructor name has been deduced through vtable.')
        return
    
    force_apply_tinfo(class_ea, obj_class_tif)

    member_value_count = get_dword(class_ea + 0x40)
    member_value_array_ea = get_qword(class_ea + 0x48)

    if member_value_count != 0 and member_value_array_ea != 0:
        force_apply_tinfo_array(member_value_array_ea, rfl_member_value_tif, member_value_count)

    class_members_var = StaticObjectVar('gameObjectClassMembers', rflclass_member_value_class_name, StaticObjectVarType.ARRAY, True)
    class_var = StaticObjectVar('gameObjectClass', class_class_name, StaticObjectVarType.VAR, True)

    set_static_var_name(member_value_array_ea, class_name, class_members_var)
    set_static_var_name(class_ea, class_name, class_var)

    getter_ea = get_getter_xref(class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetClass')
    else:
        print(f'warn: no GetClass function found for GameObject class at {class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(ctor_func, class_name)

def find_obj_classes():
    load_go_classes_ea = require_name_ea('?LoadGameObjectClasses@GameObjectSystem@game@hh@@SAXXZ')

    obj_class_arr_ea = read_source_op_addr(load_go_classes_ea + 0x12)

    tif = tinfo_t()
    tif.create_ptr(obj_class_tif)

    force_apply_tinfo_array(obj_class_arr_ea, tif, len(list(null_terminated_ptr_array_iterator(obj_class_arr_ea))) + 1)

    # for obj_class_ea in null_terminated_ptr_array_iterator(obj_class_arr_ea):
    #     handle_anal_exceptions(lambda: handle_obj_class(obj_class_ea))

    base_ctor_ea = require_name_ea('??0GameObject@game@hh@@QEAA@PEAVIAllocator@fnd@csl@@@Z')
    base_ctor = require_function(base_ctor_ea)

    for funcs in discover_class_hierarchy(base_ctor):
        handle_anal_exceptions(lambda: handle_obj_ctor(*funcs))
