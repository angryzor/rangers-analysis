import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from ida_bytes import get_qword, get_dword, get_byte
from ida_funcs import get_func
from ida_ua import o_reg
from ida_name import get_name, get_name_ea
from idaapi import BADADDR
from rangers_analysis.lib.util import require_type, require_name_ea, require_cstr
from rangers_analysis.lib.iterators import require_unique, null_terminated_ptr_array_iterator
from rangers_analysis.lib.funcs import require_function, find_unique_thunk
from rangers_analysis.lib.xrefs import get_code_drefs_to
from rangers_analysis.lib.analysis_exceptions import AnalysisException
from rangers_analysis.lib.ua_data_extraction import read_insn, read_source_op_addr, read_source_op_addr_from_reg_assignment, read_source_op_addr_from_mem_assignment_through_single_reg, read_source_op_imm_from_mem_assignment, decoded_insns_backward
from rangers_analysis.informed_analysis.report import handle_anal_exceptions, print_report, clear_report
from rangers_analysis.informed_analysis.static_initializers import find_static_initializers
from datetime import datetime
from collections import OrderedDict
import os
import ctypes
import re
import json

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

    # text = f'        enum class {name}{f" : {underlying_type}" if underlying_type else ""} {"{"}\n'

    values = OrderedDict()
    for i in range(0, count):
        enum_member_ea = member_arr_ea + i * rfl_enum_member_tif.get_size()
        values[require_cstr(get_qword(enum_member_ea + 8))] = ctypes.c_long(get_dword(enum_member_ea)).value
    
    # text += '        };\n\n'

    enums[name] = values

    return name

def emit_type(structs, enums, member_ea, typ, subtype = None):
    match types[typ]:
        case 'TYPE_VOID': return { 'type': 'void' }
        case 'TYPE_BOOL': return { 'type': 'bool' }
        case 'TYPE_SINT8': return { 'type': 'sint8' }
        case 'TYPE_UINT8': return { 'type': 'uint8' }
        case 'TYPE_SINT16': return { 'type': 'sint16' }
        case 'TYPE_UINT16': return { 'type': 'uint16' }
        case 'TYPE_SINT32': return { 'type': 'sint32' }
        case 'TYPE_UINT32': return { 'type': 'uint32' }
        case 'TYPE_SINT64': return { 'type': 'sint64' }
        case 'TYPE_UINT64': return { 'type': 'uint64' }
        case 'TYPE_FLOAT': return { 'type': 'float' }
        case 'TYPE_VECTOR2': return { 'type': 'vector2' }
        case 'TYPE_VECTOR3': return { 'type': 'vector3' }
        case 'TYPE_VECTOR4': return { 'type': 'vector4' }
        case 'TYPE_QUATERNION': return { 'type': 'quaternion' }
        case 'TYPE_MATRIX34': return { 'type': 'matrix34' }
        case 'TYPE_MATRIX44': return { 'type': 'matrix44' }
        case 'TYPE_POINTER': return { 'type': 'pointer', 'item_type': emit_type(structs, enums, member_ea, subtype)['type'] }
        case 'TYPE_ARRAY': return { 'type': 'array', 'item_type': emit_type(structs, enums, member_ea, subtype)['type'] }
        case 'TYPE_SIMPLE_ARRAY': return { 'type': 'array', 'item_type': emit_type(structs, enums, member_ea, subtype)['type'] }
        case 'TYPE_ENUM':
            initializer_xref = require_unique(f"Can't find an enum assigned for {member_ea:x}", [*filter(is_valid_enum_assignment_xref, get_code_drefs_to(member_ea + 0x10))])
            f = require_function(initializer_xref)

            insn = read_insn(initializer_xref)
            reg = insn.insn.Op2.reg

            for insn in decoded_insns_backward(initializer_xref, f.start_ea):
                if insn.mnem == 'mov' and insn.insn.Op1.type == o_reg and insn.insn.Op1.reg == reg:
                    enum_ea = get_qword(insn.insn.Op2.addr)
                    
                    return { 'type': 'enum', 'underlying_type': emit_type(structs, enums, member_ea, subtype)['type'], 'enum': emit_enum(enums, enum_ea) }

            raise AnalysisException("couldn't find an enum assignment")
        case 'TYPE_STRUCT':
            return { 'type': 'struct', 'struct': emit_struct(structs, get_qword(member_ea + 0x8)) }

        case 'TYPE_FLAGS': return { 'type': 'flags', 'underlying_type': emit_type(structs, enums, member_ea, subtype)['type'] }
        case 'TYPE_CSTRING': return { 'type': 'cstring' }
        case 'TYPE_STRING': return { 'type': 'string' }
        case 'TYPE_OBJECT_ID': return { 'type': 'csetobjectid' }
        case 'TYPE_POSITION': return { 'type': 'position' }
        case 'TYPE_COLOR_BYTE': return { 'type': 'color8' }
        case 'TYPE_COLOR_FLOAT': return { 'type': 'colorF' }

def emit_member(structs, enums, members, member_ea):
    typ = get_byte(member_ea + 0x18)
    subtype = get_byte(member_ea + 0x19)
    arr_len = get_dword(member_ea + 0x1C)
    offset = get_dword(member_ea + 0x24)

    members.append({ 'name': require_cstr(get_qword(member_ea)), **emit_type(structs, enums, member_ea, typ, subtype), 'offset': offset, **({ 'array_length': arr_len } if arr_len != 0 else {}) })


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
    
    structs[name] = { 'name': name, **({ 'parent': emit_struct(structs, parent_ea) } if parent_ea != 0 else {}), 'enums': enums, 'members': members }

    return name

clear_report()

rfl_class_arr_ea = read_source_op_addr(rfl_static_setup_ea + 0x7a)

structs = OrderedDict()

for rfl_class_ea in null_terminated_ptr_array_iterator(rfl_class_arr_ea):
    print(f'top level: handling class {rfl_class_ea:x}')
    handle_anal_exceptions(lambda: emit_struct(structs, rfl_class_ea))

f = open(f'rangers-rfl.json', 'w')
f.write(json.dumps(structs, indent=2))
f.close()

print_report()