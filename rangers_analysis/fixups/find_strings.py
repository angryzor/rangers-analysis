from ida_bytes import is_unknown, get_flags, get_max_strlit_length, ALOPT_IGNCLT, ALOPT_IGNHEADS, del_items, create_strlit
from ida_nalt import STRTYPE_C

def find_strings(seg):
    cur_ea = seg.start_ea

    while cur_ea < seg.end_ea:
        if is_unknown(get_flags(cur_ea)):
            strlen = get_max_strlit_length(cur_ea, STRTYPE_C, ALOPT_IGNCLT | ALOPT_IGNHEADS)

            if strlen > 5:
                del_items(cur_ea, 0, strlen)
                create_strlit(cur_ea, strlen, 0)
                cur_ea += strlen
                continue
        
        cur_ea += 1
