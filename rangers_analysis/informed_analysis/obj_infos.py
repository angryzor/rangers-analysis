from ida_bytes import get_qword, get_dword, get_flags, is_strlit
from ida_typeinf import tinfo_t, idc_guess_type
from ida_segment import getseg, get_segm_name
from rangers_analysis.lib.funcs import ensure_functions, find_implementation, require_function
from rangers_analysis.lib.heuristics import get_best_class_name, require_constructor_thunk_from_instantiator, discover_class_hierarchy, get_getter_xref
from rangers_analysis.lib.util import get_cstr, require_type, force_apply_tinfo, force_apply_tinfo_array, require_name_ea
from rangers_analysis.lib.naming import set_generated_vtable_name_through_ctor, set_public_instantiator_func_name, set_simple_constructor_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVarType, StaticObjectVar, friendly_class_name
from rangers_analysis.lib.ua_data_extraction import read_source_op_addr
from rangers_analysis.lib.iterators import null_terminated_ptr_array_iterator
from rangers_analysis.lib.xrefs import get_drefs_to
from rangers_analysis.lib.segments import data_seg
from .report import handle_anal_exceptions

obj_info_class_tif = require_type('hh::game::ObjInfoClass')

class_class_name = ['ObjInfoClass', 'game', 'hh']

# High confidence analysis for ObjInfos in the registry
def handle_obj_class(obj_info_class_ea):
    name_ea = get_qword(obj_info_class_ea)
    instantiator_thunk_ea = get_qword(obj_info_class_ea + 0x8)

    print(f'info: handling ObjInfoClass at {obj_info_class_ea:x}: {get_cstr(name_ea)}')

    force_apply_tinfo(obj_info_class_ea, obj_info_class_tif)

    instantiator_thunk = ensure_functions(instantiator_thunk_ea)
    instantiator = find_implementation(instantiator_thunk)
    constructor_thunk = require_constructor_thunk_from_instantiator(instantiator)
    constructor = find_implementation(constructor_thunk)

    class_name, using_fallback_name = get_best_class_name(constructor, name_ea, 'objinfos')

    class_var = StaticObjectVar('objInfoClass', class_class_name, StaticObjectVarType.VAR, True)

    set_static_var_name(obj_info_class_ea, class_name, class_var)

    set_public_instantiator_func_name(instantiator_thunk, class_name)
    if instantiator != constructor_thunk:
        set_simple_constructor_func_name(constructor_thunk, class_name)

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(constructor, class_name)

def find_obj_infos():
    obj_info_registry_ctor_ea = require_name_ea('??0ObjInfoRegistry@game@hh@@QEAA@PEAVIAllocator@fnd@csl@@@Z')

    obj_info_class_arr_ea = read_source_op_addr(obj_info_registry_ctor_ea + 0x4f)

    tif = tinfo_t()
    tif.create_ptr(obj_info_class_tif)

    force_apply_tinfo_array(obj_info_class_arr_ea, tif, len(list(null_terminated_ptr_array_iterator(obj_info_class_arr_ea))) + 1)

    for obj_info_class_ea in null_terminated_ptr_array_iterator(obj_info_class_arr_ea):
        handle_anal_exceptions(lambda: handle_obj_class(obj_info_class_ea))

    # base_ctor_ea = require_name_ea('??0ObjInfogame@hh@@QEAA@PEAVIAllocator@fnd@csl@@@Z')
    # base_ctor = require_function(base_ctor_ea)

    # for funcs in discover_class_hierarchy(base_ctor):
    #     handle_anal_exceptions(lambda: handle_obj_ctor(*funcs))
