from ida_idaapi import BADADDR
import ida_bytes
import ida_kernwin
import ida_segment

def replace_bytes():
    result, pat_start_ea, pat_end_ea = ida_kernwin.read_range_selection(None)

    if not result:
        return()

    print(f'From {pat_start_ea:x} to {pat_end_ea:x}')

    chosen_struct = ida_kernwin.choose_struc("Pick target struct")

    if chosen_struct == None:
        return()

    bts = ida_bytes.get_bytes(pat_start_ea, pat_end_ea - pat_start_ea)
    seg = ida_segment.getseg(pat_start_ea)
    pat_algn = ida_bytes.calc_max_align(pat_start_ea)
    pat_flags = ida_bytes.get_full_flags(pat_start_ea)

    print(f'Looking for bytes {bts}')

    cur_ea = seg.start_ea

    match_count = 0

    while cur_ea < seg.end_ea:
        # print(cur_ea)
        match_ea = ida_bytes.bin_search(cur_ea, seg.end_ea, bts, None, ida_bytes.BIN_SEARCH_FORWARD, 0)

        if match_ea == BADADDR:
            break

        match_flags = ida_bytes.get_full_flags(match_ea)

        if ida_bytes.calc_max_align(match_ea) >= pat_algn and (ida_bytes.is_unknown(match_flags) or ida_bytes.is_same_data_type(match_flags, pat_flags)):
            ida_bytes.create_struct(match_ea, len(bts), chosen_struct.id, True)
            match_count += 1

        cur_ea = ida_bytes.next_not_tail(match_ea)

    print(f'Found {match_count} instances')

try:
    patreplace_hotkey_ctx
    if ida_kernwin.del_hotkey(patreplace_hotkey_ctx):
        print("Hotkey unregistered!")
        del patreplace_hotkey_ctx
    else:
        print("Failed to delete hotkey!")
except:
    patreplace_hotkey_ctx = ida_kernwin.add_hotkey("Alt-Shift-Q", replace_bytes)
    if patreplace_hotkey_ctx is None:
        print("Failed to register hotkey!")
        del patreplace_hotkey_ctx
    else:
        print("Hotkey registered!")
