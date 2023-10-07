import ida_bytes
import ida_kernwin
import ida_nalt

seg = ida_kernwin.choose_segm('Which segment?', 0)

if seg == None:
    exit()

cur_ea = seg.start_ea

while cur_ea < seg.end_ea:
    if ida_bytes.is_unknown(ida_bytes.get_flags(cur_ea)):
        strlen = ida_bytes.get_max_strlit_length(cur_ea, ida_nalt.STRTYPE_C, ida_bytes.ALOPT_IGNCLT | ida_bytes.ALOPT_IGNHEADS)

        if strlen > 5:
            ida_bytes.del_items(cur_ea, 0, strlen)
            ida_bytes.create_strlit(cur_ea, strlen, 0)
            cur_ea += strlen
            continue
    
    cur_ea += 1

print('done')