from struct import unpack
from ida_bytes import get_bytes, create_byte
from ida_segment import get_segm_by_name
from rangers_analysis.lib.segments import rdata_seg
from rangers_analysis.lib.util import binsearch_matches

hhneedle_signature = b'HHNEEDLE'

def find_shaders():
    print('Looking for shaders...')

    seg = get_segm_by_name(rdata_seg)

    for ea in binsearch_matches(seg.start_ea, seg.end_ea, hhneedle_signature, None, 4):
        print(f'Found shader at offset {ea:x}')
        len_bytes = get_bytes(ea + 8, 4)
        length = unpack(">I", len_bytes)[0]

        if length == 0:
            continue

        for eai in range(ea, ea + length + 8):
            create_byte(eai, 1, True)
