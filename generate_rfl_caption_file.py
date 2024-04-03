import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from ida_bytes import get_qword, get_dword, get_byte, get_max_strlit_length, ALOPT_IGNCLT, ALOPT_IGNHEADS, del_items, create_strlit
from ida_funcs import get_func
from ida_ua import o_reg
from ida_name import get_name, get_name_ea
from ida_nalt import STRTYPE_C
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
import csv

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
rfl_custom_attribute_tif = require_type('hh::fnd::RflCustomAttribute')
rfl_class_member_tif = require_type('hh::fnd::RflClassMember')
static_initializer_eas = find_static_initializers()

def is_valid_xref(xref):
    insn = read_insn(xref)
    return insn.mnem == 'lea' and insn.insn.Op1.reg == 1

def emit_member(captions, member_ea):
    typ = get_byte(member_ea + 0x18)
    subtype = get_byte(member_ea + 0x19)
    attr_addr = get_qword(member_ea + 0x28)

    if typ == 21 or subtype == 21:
        emit_struct(captions, get_qword(member_ea + 0x8))

    if attr_addr != 0:
        attr_arr_addr = get_qword(attr_addr)
        count = get_qword(attr_addr + 8)

        for i in range(0, count):
            attr_arr_item_addr = attr_arr_addr + i * rfl_custom_attribute_tif.get_size()

            if get_qword(attr_arr_item_addr + 0x10) == 0x1440B7710:
                caption_addr = get_qword(attr_arr_item_addr + 8)
                caption_str_addr = get_qword(caption_addr)
                strlen = get_max_strlit_length(caption_str_addr, STRTYPE_C, ALOPT_IGNCLT | ALOPT_IGNHEADS)
                del_items(caption_str_addr, 0, strlen)
                create_strlit(caption_str_addr, strlen, 0)
                
                if caption_str_addr not in captions:
                    captions[caption_str_addr] = { 'caption': require_cstr(caption_str_addr), 'usedin': set() }
                
                captions[caption_str_addr]['usedin'].add(require_cstr(get_qword(member_ea)))

                return

visited_structs = set()

def emit_struct(captions, rfl_class_ea):
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

        members_ea = read_source_op_addr_from_mem_assignment_through_single_reg(initializer_func_ea, 0x30)
        members_count = read_source_op_imm_from_mem_assignment(initializer_func_ea, 0x38)

    if name in visited_structs:
        return name

    visited_structs.add(name)
    
    if parent_ea != 0:
        emit_struct(captions, parent_ea)

    for i in range(0, members_count):
        emit_member(captions, members_ea + i * rfl_class_member_tif.get_size())

clear_report()

rfl_class_arr_ea = read_source_op_addr(rfl_static_setup_ea + 0x83)

captions = dict()

for rfl_class_ea in null_terminated_ptr_array_iterator(rfl_class_arr_ea):
    print(f'top level: handling class {rfl_class_ea:x}')
    handle_anal_exceptions(lambda: emit_struct(captions, rfl_class_ea))

f = open(f'rangers-rfl-i18n.csv', 'w', -1, 'utf-8', newline='')
csvw = csv.writer(f)
for k in captions:
    print('writing', k)
    csvw.writerow([f'0x{k:x}', '/'.join(captions[k]['usedin']), captions[k]['caption']])
f.close()

print_report()