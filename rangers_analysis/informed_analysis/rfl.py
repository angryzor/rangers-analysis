from ida_bytes import get_qword
from ida_typeinf import tinfo_t
from ida_name import get_ea_name
from rangers_analysis.config import rangers_analysis_config
from rangers_analysis.lib.util import require_type, require_name_ea, require_cstr, force_apply_tinfo, force_apply_tinfo_array
from rangers_analysis.lib.iterators import require_unique, null_terminated_ptr_array_iterator
from rangers_analysis.lib.heuristics import generated_class_name, get_getter_xref
from rangers_analysis.lib.funcs import require_function, ensure_functions, require_thunk
from rangers_analysis.lib.xrefs import get_code_drefs_to, get_data_drefs_to
from rangers_analysis.lib.require import NotFoundException
from rangers_analysis.lib.ua_data_extraction import read_insn, read_source_op_addr_from_reg_assignment, read_source_op_addr_from_mem_assignment_through_single_reg, read_source_op_imm_from_mem_assignment
from rangers_analysis.lib.naming import set_generated_func_name, set_static_var_name, create_name, set_static_initializer_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType
from .report import handle_anal_exceptions

rfl_type_info_tif = require_type('hh::fnd::RflTypeInfo')
rfl_enum_member_tif = require_type('hh::fnd::RflClassEnumMember')
rfl_enum_tif = require_type('hh::fnd::RflClassEnum')
rfl_custom_attribute_tif = require_type('hh::fnd::RflCustomAttribute')
rfl_custom_attributes_tif = require_type('hh::fnd::RflCustomAttributes')
rfl_class_member_tif = require_type('hh::fnd::RflClassMember')
rfl_class_tif = require_type('hh::fnd::RflClass')

rfl_type_info_class_name = ['RflTypeInfo', 'fnd', 'hh']
rfl_class_class_name = ['RflClass', 'fnd', 'hh']
rfl_class_enum_class_name = ['RflClassEnum', 'fnd', 'hh']
rfl_class_member_class_name = ['RflClassMember', 'fnd', 'hh']

def set_rfl_type(type_info_ea):
    force_apply_tinfo(type_info_ea, rfl_type_info_tif)

    name = require_cstr(get_qword(type_info_ea))
    class_name = generated_class_name(name, 'rfl')

    print(f'info: handling RflTypeInfo at {type_info_ea:x}: {name}')

    set_static_var_name(type_info_ea, class_name, StaticObjectVar('typeInfo', rfl_type_info_class_name, StaticObjectVarType.VAR, True, True), certain=True, unique=True)

    constructor_ea = get_qword(type_info_ea + 0x10)
    finisher_ea = get_qword(type_info_ea + 0x18)
    cleaner_ea = get_qword(type_info_ea + 0x20)

    set_generated_func_name(ensure_functions(constructor_ea), create_name('?{0}@CAXPEAU{1}@PEAV{2}@@Z', ['Construct', *class_name], class_name, ['IAllocator', 'fnd', 'csl']), certain=True)
    set_generated_func_name(ensure_functions(finisher_ea), create_name('?{0}@CAXPEAU{1}@@Z', ['Finish', *class_name], class_name), certain=True)
    set_generated_func_name(ensure_functions(cleaner_ea), create_name('?{0}@CAXPEAU{1}@@Z', ['Clean', *class_name], class_name), certain=True)

def handle_rfl_enum_members(enum_members_ea, count):
    force_apply_tinfo_array(enum_members_ea, rfl_enum_member_tif, count)

def handle_rfl_enums(enums_ea, count):
    force_apply_tinfo_array(enums_ea, rfl_enum_tif, count)

    for i in range(0, count):
        enum_ea = enums_ea + i * rfl_enum_tif.get_size()

        handle_rfl_enum_members(get_qword(enum_ea + 8), get_qword(enum_ea + 16))

# def handle_rfl_custom_attr(attr_ea):
#     rfl_class_ea = get_qword(attr_ea + 0x10)
#     rfl_class_name = get_name(rfl_class_ea)

    


def handle_rfl_custom_attrs(attrs_ea, count):
    force_apply_tinfo_array(attrs_ea, rfl_custom_attribute_tif, count)

def handle_rfl_custom_attr_arr(custom_attr_arr_ea):
    force_apply_tinfo(custom_attr_arr_ea, rfl_custom_attributes_tif)

    handle_rfl_custom_attrs(get_qword(custom_attr_arr_ea), get_qword(custom_attr_arr_ea + 8))

def handle_rfl_members(members_ea, count):
    force_apply_tinfo_array(members_ea, rfl_class_member_tif, count)

    for i in range(0, count):
        member_ea = members_ea + i * rfl_class_member_tif.get_size()

        # class_ea = get_qword(member_ea + 8)
        # handle_rfl_class(class_ea)

        custom_attr_arr_ea = get_qword(member_ea + 0x28)
        if custom_attr_arr_ea != 0:
            handle_rfl_custom_attr_arr(custom_attr_arr_ea)

def is_valid_xref(xref):
    insn = read_insn(xref)
    return insn.mnem == 'lea' and insn.insn.Op1.reg == 1


def handle_rfl_class(static_initializer_eas, rfl_class_ea):
    class_var = StaticObjectVar('rflClass', rfl_class_class_name, StaticObjectVarType.VAR, True, True)

    try:
        rfl_class_cref = require_unique(f"Can't find unique non-getter xref for {rfl_class_ea:x}", [*filter(is_valid_xref, get_code_drefs_to(rfl_class_ea))])
    except NotFoundException as e:
        force_apply_tinfo(rfl_class_ea, rfl_class_tif)
        class_name = generated_class_name(f'unk_{f"{rfl_class_ea:x}".upper()}', 'rfl')
        set_static_var_name(rfl_class_ea, class_name, class_var, unique=True)
        raise e

    initializer_func = require_function(rfl_class_cref)
    initializer_thunk = require_thunk(initializer_func)
    initializer_func_ea = initializer_func.start_ea

    name_ea = read_source_op_addr_from_reg_assignment(initializer_func_ea, 2)

    force_apply_tinfo(rfl_class_ea, rfl_class_tif)

    name = require_cstr(name_ea)
    class_name = generated_class_name(name, 'rfl')

    print(f'info: handling RflClass at {rfl_class_ea:x}: {name}')

    set_static_var_name(rfl_class_ea, class_name, class_var, certain=True, unique=True)
    set_static_initializer_func_name(initializer_thunk, class_name, class_var, certain=True, unique=True)

    getter_ea = get_getter_xref(rfl_class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetClass', certain=True)
        
    members_ea = read_source_op_addr_from_mem_assignment_through_single_reg(initializer_func_ea, 0x30, initializer_func.end_ea)
    members_count = read_source_op_imm_from_mem_assignment(initializer_func_ea, 0x38, initializer_func.end_ea)

    if members_ea != 0 and members_count != 0:
        handle_rfl_members(members_ea, members_count)
        members_var = StaticObjectVar('rflClassMembers', rfl_class_member_class_name, StaticObjectVarType.ARRAY, True)
        set_static_var_name(members_ea, class_name, members_var, certain=True, unique=True)

    enums_ea = read_source_op_addr_from_mem_assignment_through_single_reg(initializer_func_ea, 0x20, initializer_func.end_ea)
    enums_count = read_source_op_imm_from_mem_assignment(initializer_func_ea, 0x28, initializer_func.end_ea)

    if enums_ea != 0 and enums_count != 0:
        handle_rfl_enums(enums_ea, enums_count)
        enums_var = StaticObjectVar('rflClassEnums', rfl_class_enum_class_name, StaticObjectVarType.ARRAY, True)
        set_static_var_name(enums_ea, class_name, enums_var, certain=True, unique=True)

        enum_ptr_ea = require_unique(f"Can't find an enum assignment for {enums_ea:x}", get_data_drefs_to(enums_ea))
        members_initializer = require_function(require_unique(f"Can't find an enum assignment for {enums_ea:x}", [*filter(lambda xref: xref in static_initializer_eas, get_code_drefs_to(enum_ptr_ea))]))
        set_static_initializer_func_name(members_initializer, class_name, members_var, certain=True, unique=True)

def set_rfl_types(rfl_type_info_arr_ea):
    tif = tinfo_t()
    tif.create_ptr(rfl_type_info_tif)

    force_apply_tinfo_array(rfl_type_info_arr_ea, tif, len(list(null_terminated_ptr_array_iterator(rfl_type_info_arr_ea))) + 1)

    for type_info_ea in null_terminated_ptr_array_iterator(rfl_type_info_arr_ea):
        handle_anal_exceptions(lambda: set_rfl_type(type_info_ea))

def set_rfl_classes(static_initializer_eas, rfl_class_arr_ea):
    tif = tinfo_t()
    tif.create_ptr(rfl_class_tif)

    force_apply_tinfo_array(rfl_class_arr_ea, tif, len(list(null_terminated_ptr_array_iterator(rfl_class_arr_ea))) + 1)

    for rfl_class_ea in null_terminated_ptr_array_iterator(rfl_class_arr_ea):
        class_name = get_ea_name(rfl_class_ea)
        if not class_name or class_name not in rangers_analysis_config['fixed_rfl_overrides']:
            handle_anal_exceptions(lambda: handle_rfl_class(static_initializer_eas, rfl_class_ea))

def find_rfl_statics(static_initializer_eas):
    rfl_type_info_arr_ea = require_name_ea('?staticRflTypeInfos@RflTypeInfoRegistry@fnd@hh@@0PAPEAVRflTypeInfo@23@A')
    rfl_class_arr_ea = require_name_ea('?staticRflClasses@RflClassNameRegistry@fnd@hh@@0PAPEAVRflClass@23@A')

    set_rfl_types(rfl_type_info_arr_ea)
    set_rfl_classes(static_initializer_eas, rfl_class_arr_ea)
