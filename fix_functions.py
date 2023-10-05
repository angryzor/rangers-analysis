import ida_bytes
import ida_kernwin
import ida_segment
import ida_funcs

seg = ida_kernwin.choose_segm('Which data segment?', 0)
codeseg = ida_kernwin.choose_segm('Which code segment?', 0)

if seg == None or codeseg == None:
    exit()

cur_ea = seg.start_ea

while cur_ea < seg.end_ea:
    ref_flags = ida_bytes.get_full_flags(cur_ea)

    if ida_bytes.is_qword(ref_flags):
        func_ea = ida_bytes.get_qword(cur_ea)
    
        if ida_segment.getseg(func_ea) == codeseg:
            func_flags = ida_bytes.get_full_flags(func_ea)

            if ida_bytes.is_tail(func_flags):
                head_ea = ida_bytes.get_item_head(func_ea)
                head_flags = ida_bytes.get_full_flags(head_ea)

                if ida_bytes.is_qword(head_flags):
                    ida_bytes.del_items(head_ea, 0, ida_bytes.get_item_size(head_ea))

                    func_flags = ida_bytes.get_full_flags(func_ea)

            if ida_bytes.is_unknown(func_flags):
                ida_funcs.add_func(func_ea)
                ida_bytes.del_items(cur_ea, 0, 8)
                ida_bytes.create_qword(cur_ea, 8)
    
    cur_ea += 8

print('done')