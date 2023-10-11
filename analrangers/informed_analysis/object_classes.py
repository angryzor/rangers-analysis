from ida_bytes import get_qword, get_dword
from ida_typeinf import tinfo_t
from analrangers.lib.funcs import ensure_functions, find_implementation
from analrangers.lib.heuristics import get_best_class_name, require_constructor_thunk_from_instantiator
from analrangers.lib.util import get_cstr, class_name_to_backrefs, require_type, force_apply_tinfo, force_apply_tinfo_array, require_name_ea
from analrangers.lib.naming import set_generated_vtable_name_through_ctor, set_generated_func_name, set_generated_name
from analrangers.lib.ua_data_extraction import read_source_op_addr
from analrangers.lib.iterators import null_terminated_ptr_array_iterator
from .report import handle_anal_exceptions

obj_class_tif = require_type('hh::game::GameObjectClass')
rfl_member_value_tif = require_type('hh::fnd::RflClassMember::Value')

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
    
    set_generated_name(member_value_array_ea, f'?staticClassMembers@{class_name}@@0PEAVValue@RflClassMember@fnd@hh@@EA')

    set_generated_name(obj_class_ea, f'?staticClass@{class_name}@@0PEAVGameObjectClass@game@hh@@EA')
    set_generated_func_name(instantiator_thunk, f'?Instantiate@{class_name}@@CAPEAV{class_name_to_backrefs(class_name)}@PEAVIAllocator@fnd@csl@@@Z')
    if instantiator != constructor_thunk:
        set_generated_func_name(constructor_thunk, f'??0{class_name}@@QEAA@PEAVIAllocator@fnd@csl@@@Z')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(constructor, class_name)

def find_obj_classes():
    load_go_classes_ea = require_name_ea('?LoadGameObjectClasses@GameObjectSystem@game@hh@@SAXXZ')

    obj_class_arr_ea = read_source_op_addr(load_go_classes_ea + 0x12)

    tif = tinfo_t()
    tif.create_ptr(obj_class_tif)

    force_apply_tinfo_array(obj_class_arr_ea, tif, len(list(null_terminated_ptr_array_iterator(obj_class_arr_ea))) + 1)

    for obj_class_ea in null_terminated_ptr_array_iterator(obj_class_arr_ea):
        handle_anal_exceptions(lambda: handle_obj_class(obj_class_ea))
