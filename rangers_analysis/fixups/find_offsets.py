from ida_bytes import is_unknown, get_qword, create_qword, next_not_tail, get_full_flags, calc_max_align
from ida_segment import getseg
from ida_offset import op_plain_offset
from ida_typeinf import idc_get_type

def find_offsets(seg):
    cur_ea = seg.start_ea

    while cur_ea < seg.end_ea:
        ref_flags = get_full_flags(cur_ea)

        if calc_max_align(cur_ea) >= 3 and is_unknown(ref_flags) or idc_get_type(cur_ea) == None:
            func_ea = get_qword(cur_ea)
        
            if getseg(func_ea) != None:
                create_qword(cur_ea, 8)
                op_plain_offset(cur_ea, 0, 0)
        
        cur_ea = next_not_tail(cur_ea)
