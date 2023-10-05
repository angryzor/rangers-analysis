from ida_xref import get_first_cref_to, get_next_cref_to, get_first_dref_to, get_next_dref_to
from ida_segment import get_segm_name, getseg
from .iterators import ea_iterator
from .segments import data_seg, rdata_seg, text_seg, denuvoized_text_seg

get_crefs_to = ea_iterator(get_first_cref_to, get_next_cref_to)
get_drefs_to = ea_iterator(get_first_dref_to, get_next_dref_to)

def in_segments(segs, crefs):
    return filter(lambda cref: get_segm_name(getseg(cref)) in segs, crefs)

def get_code_drefs_to(ea):
    return in_segments([text_seg, denuvoized_text_seg], get_drefs_to(ea))

def get_data_drefs_to(ea):
    return in_segments([rdata_seg, data_seg], get_drefs_to(ea))

def get_safe_crefs_to(ea):
    return in_segments([text_seg, denuvoized_text_seg], get_crefs_to(ea))
