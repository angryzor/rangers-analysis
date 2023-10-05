from ida_idaapi import BADADDR
import ida_bytes
import ida_kernwin

def add_aligns():
    result, cur_ea, max_ea = ida_kernwin.read_range_selection(None)

    if not result:
        exit()

    print(f'From {cur_ea:x} to {max_ea:x}')

    cur_ea -= 1
    align_count = 0

    while cur_ea < max_ea:
        unknown_ea = ida_bytes.next_unknown(cur_ea, max_ea)

        if unknown_ea == BADADDR:
            break

        known_ea = ida_bytes.next_head(unknown_ea, max_ea)

        if known_ea == BADADDR:
            known_ea = max_ea
        
        undefined_run_length = known_ea - unknown_ea

        ida_bytes.create_align(unknown_ea, undefined_run_length, 0)
        # print(f'Would go from {unknown_ea:x} to {known_ea - 1:x}')

        align_count += 1

        cur_ea = known_ea

    print(f'Inserted {align_count} aligns')

try:
    align_hotkey_ctx
    if ida_kernwin.del_hotkey(align_hotkey_ctx):
        print("Hotkey unregistered!")
        del align_hotkey_ctx
    else:
        print("Failed to delete hotkey!")
except:
    align_hotkey_ctx = ida_kernwin.add_hotkey("Shift-L", add_aligns)
    if align_hotkey_ctx is None:
        print("Failed to register hotkey!")
        del align_hotkey_ctx
    else:
        print("Hotkey registered!")
