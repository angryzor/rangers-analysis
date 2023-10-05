import ida_bytes
import ida_kernwin
import ida_segment
import ida_typeinf
import ida_offset
from ida_netnode import BADNODE

seg = ida_kernwin.choose_segm('Which segment?', 0)

if seg == None:
    exit()

cur_ea = seg.start_ea

while cur_ea < seg.end_ea:
    ref_flags = ida_bytes.get_full_flags(cur_ea)

    if ida_bytes.calc_max_align(cur_ea) >= 3 and ida_bytes.is_unknown(ref_flags) or ida_typeinf.idc_get_type(cur_ea) == None:
        func_ea = ida_bytes.get_qword(cur_ea)
    
        if ida_segment.getseg(func_ea) != None:
            ida_bytes.create_qword(cur_ea, 8)
            ida_offset.op_plain_offset(cur_ea, 0, 0)
    
    cur_ea = ida_bytes.next_not_tail(cur_ea)

print('done')
