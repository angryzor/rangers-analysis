import sys

analmodules = [mod for mod in sys.modules if mod.startswith('analrangers')]
for mod in analmodules:
    del sys.modules[mod]

from ida_bytes import get_qword, get_dword, get_byte
from ida_funcs import get_func
from ida_ua import o_reg
from ida_name import get_name, get_name_ea
from idaapi import BADADDR
from analrangers.lib.util import require_type, require_name_ea, require_cstr
from analrangers.lib.iterators import require_unique, null_terminated_ptr_array_iterator
from analrangers.lib.funcs import require_function, find_unique_thunk
from analrangers.lib.xrefs import get_code_drefs_to
from analrangers.lib.analysis_exceptions import AnalException
from analrangers.lib.ua_data_extraction import read_insn, read_source_op_addr, read_source_op_addr_from_reg_assignment, read_source_op_addr_from_mem_assignment_through_single_reg, read_source_op_imm_from_mem_assignment, decoded_insns_backward
from analrangers.informed_analysis.report import handle_anal_exceptions, print_report, clear_report
from analrangers.informed_analysis.static_initializers import find_static_initializers
from datetime import datetime
from collections import OrderedDict
import os
import ctypes
import re

# because of denuvo obfuscating some static initializers -_-
fixed_overrides = {
    'DetailMesh': { 'member_count': 2, 'parent': 0 },
    'OffMeshLinkParameter': { 'member_count': 1, 'parent': 0 },
    'Partitioning': { 'member_count': 1, 'parent': 0 },
    'Polygonization': { 'member_count': 3, 'parent': 0 },
    'Rasterization': { 'member_count': 2, 'parent': 0 },
    'Region': { 'member_count': 2, 'parent': 0 },
    'World': { 'member_count': 2, 'parent': 0 },
    'FxBrunetonSky': { 'member_count': 19, 'parent': 0 },
    'FxBrunetonSkyNight': { 'member_count': 8, 'parent': 0 },
    'FxCloudBlendParameter': { 'member_count': 4, 'parent': 0 },
    'FxCloudProcedural': { 'member_count': 4, 'parent': 0 },
    'FxCloudShadowParameter': { 'member_count': 3, 'parent': 0 },
    'FxCrepuscularRay': { 'member_count': 4, 'parent': 0 },
    'FxDensityParameter': { 'member_count': 19, 'parent': 0 },
    'FxDensityLodParameter': { 'member_count': 5, 'parent': 0 },
    'FxDensityDebugParameter': { 'member_count': 14, 'parent': 0 },
    'ColorDropout': { 'member_count': 6, 'parent': 0 },
    'ColorShift': { 'member_count': 4, 'parent': 0 },
    'DebugScreenOption': { 'member_count': 10, 'parent': 0 },
    'FxAntiAliasing': { 'member_count': 3, 'parent': 0 },
    'FxBloomParameter': { 'member_count': 5, 'parent': 0 },
    'FxCameraControlParameter': { 'member_count': 3, 'parent': 0 },
    'FxChromaticAberrationParameter': { 'member_count': 9, 'parent': 0 },
    'FxColorAccessibilityFilterParameter': { 'member_count': 9, 'parent': 0 },
    'FxColorContrastParameter': { 'member_count': 17, 'parent': 0 },
    'FxCyberSpaceStartNoiseParameter': { 'member_count': 11, 'parent': 0 },
    'FxDOFParameter': { 'member_count': 22, 'parent': 0 },
}

rfl_static_setup_ea = require_name_ea('?Instantiate@BuiltinTypeRegistry@fnd@hh@@SAPEAV123@XZ')
rfl_enum_member_tif = require_type('hh::fnd::RflClassEnumMember')
rfl_enum_tif = require_type('hh::fnd::RflClassEnum')
rfl_class_member_tif = require_type('hh::fnd::RflClassMember')
static_initializer_eas = find_static_initializers()

types = {
	0: 'TYPE_VOID',
	1: 'TYPE_BOOL',
	2: 'TYPE_SINT8',
	3: 'TYPE_UINT8',
	4: 'TYPE_SINT16',
	5: 'TYPE_UINT16',
	6: 'TYPE_SINT32',
	7: 'TYPE_UINT32',
	8: 'TYPE_SINT64',
	9: 'TYPE_UINT64',
	10: 'TYPE_FLOAT',
	11: 'TYPE_VECTOR2',
	12: 'TYPE_VECTOR3',
	13: 'TYPE_VECTOR4',
	14: 'TYPE_QUATERNION',
	15: 'TYPE_MATRIX34',
	16: 'TYPE_MATRIX44',
	17: 'TYPE_POINTER',
	18: 'TYPE_ARRAY',
	19: 'TYPE_SIMPLE_ARRAY',
	20: 'TYPE_ENUM',
	21: 'TYPE_STRUCT',
	22: 'TYPE_FLAGS',
	23: 'TYPE_CSTRING',
	24: 'TYPE_STRING',
	25: 'TYPE_OBJECT_ID',
	26: 'TYPE_POSITION',
	27: 'TYPE_COLOR_BYTE',
	28: 'TYPE_COLOR_FLOAT',
}

enum_sizes = {
	0: 0,
	1: 1,
	2: 1,
	3: 1,
	4: 2,
	5: 2,
	6: 4,
	7: 4,
	8: 8,
	9: 8,
	10: 4,
}

def is_valid_xref(xref):
    insn = read_insn(xref)
    return insn.mnem == 'lea' and insn.insn.Op1.reg == 1

def is_valid_enum_assignment_xref(xref):
    f = get_func(xref)
    return f and find_unique_thunk(f).start_ea in static_initializer_eas

def emit_enum(enums, enum_ea, underlying_type = None):
    name = require_cstr(get_qword(enum_ea))
    member_arr_ea = get_qword(enum_ea + 8)
    count = get_qword(enum_ea + 16)

    text = f'        enum class {name}{f" : {underlying_type}" if underlying_type else ""} {"{"}\n'

    for i in range(0, count):
        enum_member_ea = member_arr_ea + i * rfl_enum_member_tif.get_size()

        text += f'            {require_cstr(get_qword(enum_member_ea + 8))} = {ctypes.c_long(get_dword(enum_member_ea)).value},\n'
    
    text += '        };\n\n'

    enums[name] = text
    
    return name

def emit_type(structs, enums, member_ea, typ, subtype = None):
    match types[typ]:
        case 'TYPE_VOID': return 'void'
        case 'TYPE_BOOL': return 'bool'
        case 'TYPE_SINT8': return 'int8_t'
        case 'TYPE_UINT8': return 'uint8_t'
        case 'TYPE_SINT16': return 'int16_t'
        case 'TYPE_UINT16': return 'uint16_t'
        case 'TYPE_SINT32': return 'int32_t'
        case 'TYPE_UINT32': return 'uint32_t'
        case 'TYPE_SINT64': return 'int64_t'
        case 'TYPE_UINT64': return 'uint64_t'
        case 'TYPE_FLOAT': return 'float'
        case 'TYPE_VECTOR2': return 'csl::math::Vector2'
        case 'TYPE_VECTOR3': return 'csl::math::Vector3'
        case 'TYPE_VECTOR4': return 'csl::math::Vector4'
        case 'TYPE_QUATERNION': return 'csl::math::Quaternion'
        case 'TYPE_MATRIX34': return 'csl::math::Matrix34'
        case 'TYPE_MATRIX44': return 'csl::math::Matrix44'
        case 'TYPE_POINTER': return 'void*'
        case 'TYPE_ARRAY': return f'csl::ut::MoveArray<{emit_type(structs, enums, member_ea, subtype)}>'
        case 'TYPE_SIMPLE_ARRAY': return f'{emit_type(structs, enums, member_ea, subtype)}*'
        case 'TYPE_ENUM':
            initializer_xref = require_unique(f"Can't find an enum assigned for {member_ea:x}", [*filter(is_valid_enum_assignment_xref, get_code_drefs_to(member_ea + 0x10))])
            f = require_function(initializer_xref)

            insn = read_insn(initializer_xref)
            reg = insn.insn.Op2.reg

            for insn in decoded_insns_backward(initializer_xref, f.start_ea):
                if insn.mnem == 'mov' and insn.insn.Op1.type == o_reg and insn.insn.Op1.reg == reg:
                    enum_ea = get_qword(insn.insn.Op2.addr)
                    
                    return emit_enum(enums, enum_ea, emit_type(structs, enums, member_ea, subtype))

            raise AnalException("couldn't find an enum assignment")
        case 'TYPE_STRUCT':
            return emit_struct(structs, get_qword(member_ea + 0x8))

        case 'TYPE_FLAGS': return f'csl::ut::Bitset<{emit_type(structs, enums, member_ea, subtype)}>'
        case 'TYPE_CSTRING': return 'char*'
        case 'TYPE_STRING': return 'csl::ut::VariableString'
        case 'TYPE_OBJECT_ID': return 'hh::game::ObjectId'
        case 'TYPE_POSITION': return 'csl::math::Vector3'
        case 'TYPE_COLOR_BYTE': return 'csl::ut::Color<uint8_t>'
        case 'TYPE_COLOR_FLOAT': return 'csl::ut::Color<float>'

def emit_member(structs, enums, members, member_ea):
    typ = get_byte(member_ea + 0x18)
    subtype = get_byte(member_ea + 0x19)
    arr_len = get_dword(member_ea + 0x1C)

    members.append(f'        {emit_type(structs, enums, member_ea, typ, subtype)} {require_cstr(get_qword(member_ea))}{f"[{arr_len}]" if arr_len != 0 else ""};\n')


visited_structs = set()

def emit_struct(structs, rfl_class_ea):
    enums = OrderedDict()
    members = []

    m = re.match(r'\?rflClass@([A-Za-z]+)@rfl@app@@2VRflClass@fnd@hh@@B', get_name(rfl_class_ea))

    if m and m.group(1) in fixed_overrides:
        name = m.group(1)
        print(f'info: handling rfl class at {rfl_class_ea:x}: {name}')

        parent_ea = fixed_overrides[name]['parent']

        members_ea = get_name_ea(BADADDR, f'?rflClassMembers@{name}@rfl@app@@0QBVRflClassMember@fnd@hh@@B')
        members_count = fixed_overrides[name]['member_count']
    else:
        rfl_class_cref = require_unique(f"Can't find unique non-getter xref for {rfl_class_ea:x}", [*filter(is_valid_xref, get_code_drefs_to(rfl_class_ea))])

        initializer_func = require_function(rfl_class_cref)
        initializer_func_ea = initializer_func.start_ea

        name = require_cstr(read_source_op_addr_from_reg_assignment(initializer_func_ea, 2))
        print(f'info: handling rfl class at {rfl_class_ea:x}: {name}')

        parent_ea = read_source_op_addr_from_reg_assignment(initializer_func_ea, 8)

        enums_ea = read_source_op_addr_from_mem_assignment_through_single_reg(initializer_func_ea, 0x20)
        enums_count = read_source_op_imm_from_mem_assignment(initializer_func_ea, 0x28)
        
        members_ea = read_source_op_addr_from_mem_assignment_through_single_reg(initializer_func_ea, 0x30)
        members_count = read_source_op_imm_from_mem_assignment(initializer_func_ea, 0x38)

    if name in visited_structs:
        return name

    visited_structs.add(name)

    if name not in fixed_overrides:
        # To handle unreferenced enums, we currently just skip this for the denuvo'd enums.
        for i in range(0, enums_count):
            emit_enum(enums, enums_ea + i * rfl_enum_tif.get_size())
    
    for i in range(0, members_count):
        emit_member(structs, enums, members, members_ea + i * rfl_class_member_tif.get_size())
    
    text = f'    struct {name}{f" : {emit_struct(structs, parent_ea)}" if parent_ea != 0 else ""} {"{"}\n'

    for k in enums:
        text += enums[k]
    
    for m in members:
        text += m
    
    text +=  '\n'
    text +=  '        static const hh::fnd::RflTypeInfo typeInfo;\n'
    text +=  '        static const hh::fnd::RflClass rflClass;\n'
    text +=  '    private:\n'
    text += f'        static void Construct({name}* pInstance, csl::fnd::IAllocator* pAllocator);\n'
    text += f'        static void Finish({name}* pInstance);\n'
    text += f'        static void Clean({name}* pInstance);\n'
    text +=  '    };\n\n'

    structs[name] = text

    return name

clear_report()

rfl_class_arr_ea = read_source_op_addr(rfl_static_setup_ea + 0x7a)

structs = OrderedDict()

for rfl_class_ea in null_terminated_ptr_array_iterator(rfl_class_arr_ea):
    print(f'top level: handling class {rfl_class_ea:x}')
    handle_anal_exceptions(lambda: emit_struct(structs, rfl_class_ea))

f = open(f'rangers-rfl.h', 'w')
f.write('namespace app::rfl {\n')
for k in structs:
    print('writing', k)
    f.write(structs[k])
f.write('}\n')
f.close()

print_report()