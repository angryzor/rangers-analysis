from ida_bytes import is_unknown, is_qword, get_qword, create_qword, is_tail, get_item_head, get_item_size, get_full_flags, del_items
from ida_segment import getseg
from ida_funcs import add_func

def fix_functions(data_seg, code_seg):
    cur_ea = data_seg.start_ea

    while cur_ea < data_seg.end_ea:
        ref_flags = get_full_flags(cur_ea)

        if is_qword(ref_flags):
            func_ea = get_qword(cur_ea)
        
            if getseg(func_ea) == code_seg:
                func_flags = get_full_flags(func_ea)

                if is_tail(func_flags):
                    head_ea = get_item_head(func_ea)
                    head_flags = get_full_flags(head_ea)

                    if is_qword(head_flags):
                        del_items(head_ea, 0, get_item_size(head_ea))

                        func_flags = get_full_flags(func_ea)

                if is_unknown(func_flags):
                    add_func(func_ea)
                    del_items(cur_ea, 0, 8)
                    create_qword(cur_ea, 8)
        
        cur_ea += 8
