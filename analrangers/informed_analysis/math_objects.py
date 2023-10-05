from ida_bytes import set_cmt, get_bytes, is_unknown, is_oword, get_flags, is_dword, get_dword, calc_max_align, get_item_size, is_qword
from ida_segment import get_segm_by_name
from ida_typeinf import TINFO_GUESSED, idc_guess_type, tinfo_t, BTF_FLOAT
from analrangers.lib.util import require_type, binsearch_matches, force_apply_tinfo_array, force_apply_tinfo, not_tails
from analrangers.lib.segments import rdata_seg
from .report import handle_anal_exceptions
from ctypes import cast, pointer, c_long, c_float, POINTER

quat_tif = require_type('csl::math::Quaternion')
v4_tif = require_type('csl::math::Vector4')
mat44_tif = require_type('csl::math::Matrix44')
float_tif = tinfo_t()
float_tif.create_simple_type(BTF_FLOAT)

numbers = {
    '0': b'\x00\x00\x00\x00',
    '1': b'\x00\x00\x80\x3F',
    '-1': b'\x00\x00\x80\xBF',
    'pi': b'\xDB\x0F\x49\x40',
    '-pi': b'\xDB\x0F\x49\xC0',
    'tau': b'\xDB\x0F\xC9\x40',
    '-tau': b'\xDB\x0F\xC9\xC0',
    'pi / 2': b'\xDB\x0F\xC9\x3F',
    '1 / tau': b'\x83\xF9\x22\x3E',
    '1 / 4': b'\x00\x00\x80\x3E',
    'nan': b'\x00\x00\xC0\x7F',
    'floatprecision': b'\x00\x00\x00\x34',
    '60 degrees in radians': b'\x92\x0A\x86\x3F',
    '75 degrees in radians': b'\x36\x8D\xA7\x3F',
    '150 degrees in radians': b'\x36\x8D\x27\x40',
}

masks = {
    'none': b'\x00\x00\x00\x00',
    'exp': b'\x00\x00\x80\x7F',
    'abs': b'\xFF\xFF\xFF\x7F',
    'sign': b'\x00\x00\x00\x80',
    'unknown': b'\x00\x00\x00\x4B',
    'all': b'\xFF\xFF\xFF\xFF',
}

originvec = numbers['0'] + numbers['0'] + numbers['0'] + numbers['0']

commonvectors = {
    'basis x': numbers['1'] + numbers['0'] + numbers['0'] + numbers['0'],
    'basis y': numbers['0'] + numbers['1'] + numbers['0'] + numbers['0'],
    'basis z': numbers['0'] + numbers['0'] + numbers['1'] + numbers['0'],

    # not sure about these at all
    'mirror over x axis': numbers['1'] + numbers['-1'] + numbers['-1'] + numbers['1'],
    'mirror over y axis': numbers['-1'] + numbers['1'] + numbers['-1'] + numbers['1'],
    'mirror over z axis': numbers['-1'] + numbers['-1'] + numbers['1'] + numbers['1'],
    'mirror over yz plane': numbers['-1'] + numbers['1'] + numbers['1'] + numbers['1'],
    'mirror over xz plane': numbers['1'] + numbers['-1'] + numbers['1'] + numbers['1'],
    'mirror over xy plane': numbers['1'] + numbers['1'] + numbers['-1'] + numbers['1'],
    'mirror over origin': numbers['-1'] + numbers['-1'] + numbers['-1'] + numbers['1'],

    'unit xyz': numbers['1'] + numbers['1'] + numbers['1'] + numbers['0'],
    'unit xyzw': numbers['1'] + numbers['1'] + numbers['1'] + numbers['1'],
    'negative unit xyz': numbers['-1'] + numbers['-1'] + numbers['-1'] + numbers['0'],
    'negative unit xyzw': numbers['-1'] + numbers['-1'] + numbers['-1'] + numbers['-1'],
    
    'mask all xyzw': masks['all'] + masks['all'] + masks['all'] + masks['all'],
    'mask all xyz': masks['all'] + masks['all'] + masks['all'] + masks['none'],
    'mask all x': masks['all'] + masks['none'] + masks['none'] + masks['none'],
    'mask all y': masks['none'] + masks['all'] + masks['none'] + masks['none'],
    'mask all z': masks['none'] + masks['none'] + masks['all'] + masks['none'],
    'mask unknown xyzw': masks['unknown'] + masks['unknown'] + masks['unknown'] + masks['unknown'],
    'mask sign xyzw': masks['sign'] + masks['sign'] + masks['sign'] + masks['sign'],
    'mask sign xyz': masks['sign'] + masks['sign'] + masks['sign'] + masks['none'],
    'mask abs xyzw': masks['abs'] + masks['abs'] + masks['abs'] + masks['abs'],
    'mask abs xyz': masks['abs'] + masks['abs'] + masks['abs'] + masks['none'],
    'mask exp xyzw': masks['exp'] + masks['exp'] + masks['exp'] + masks['exp'],
    'mask exp xyz': masks['exp'] + masks['exp'] + masks['exp'] + masks['none'],
    
    'quaternion multtable i': numbers['1'] + numbers['-1'] + numbers['1'] + numbers['-1'],
    'quaternion multtable j': numbers['1'] + numbers['1'] + numbers['-1'] + numbers['-1'],
    'quaternion multtable k': numbers['-1'] + numbers['1'] + numbers['1'] + numbers['-1'],

    'pi xyzw': numbers['pi'] + numbers['pi'] + numbers['pi'] + numbers['pi'],
    'tau xyzw': numbers['tau'] + numbers['tau'] + numbers['tau'] + numbers['tau'],
    'pi / 2 xyzw': numbers['pi / 2'] + numbers['pi / 2'] + numbers['pi / 2'] + numbers['pi / 2'],
    '1 / tau xyzw': numbers['1 / tau'] + numbers['1 / tau'] + numbers['1 / tau'] + numbers['1 / tau'],
    '1 / 4 xyzw': numbers['1 / 4'] + numbers['1 / 4'] + numbers['1 / 4'] + numbers['1 / 4'],
    'nan xyzw': numbers['nan'] + numbers['nan'] + numbers['nan'] + numbers['nan'],
    'floatprecision xyzw': numbers['floatprecision'] + numbers['floatprecision'] + numbers['floatprecision'] + numbers['floatprecision'],
}

commonquats = {
    'unit quaternion': numbers['0'] + numbers['0'] + numbers['0'] + numbers['1'],
}

commonmats = {
    'identity': commonvectors['basis x'] + commonvectors['basis y'] + commonvectors['basis z'] + commonquats['unit quaternion']
}

commonfloatarrays = {
    'sine minimax approximation coeffs degree 11': b'\xab\xaa*\xbe\x86\x88\x08<\xf1\x0bP\xb9\x8e\xb886[6\xcd\xb2',
    'sine minimax approximation coeffs degree 7': b'\x88\xa8*\xbe<7\x08<\xc8>B\xb9',
    'cosine minimax approximation coeffs degree 10': b'\x00\x00\x00\xbf\xa3\xaa*=\xaa\t\xb6\xba\xc2\xb4\xcf7\x11\xdd\x8b\xb4',
    'cosine minimax approximation coeffs degree 6': b'~\xf6\xff\xbe\x87\xf5)=\xdb\x9f\xa6\xba',
}

def match_bytes(seg, d, tif, align, make_array = False):
    tif_size = tif.get_size()
    
    for k in d:
        print(f'info: finding matches for `{k}`')
        for ea in binsearch_matches(seg.start_ea, seg.end_ea, d[k], None, align):
            flags = get_flags(ea)
            typ = idc_guess_type(ea)
            typ = typ and typ.split('[')[0]

            if is_unknown(flags) or is_oword(flags) or (tif.get_size() == 16 and is_qword(flags) and (is_unknown(get_flags(ea + 8)) or is_qword(get_flags(ea + 8)))) or (get_item_size(ea) == tif.get_size() and typ in ('V4', 'float', 'csl::math::Vector4', 'csl::math::Matrix44', 'csl::math::Quaternion')):
                print(f'info: found `{k}` instance at {ea:x}')

                if make_array:
                    force_apply_tinfo_array(ea, tif, len(d[k]) // tif_size, TINFO_GUESSED)
                else:
                    force_apply_tinfo(ea, tif, TINFO_GUESSED)

                set_cmt(ea, k, True)

def looks_like_float(v, allow_zero = False):
    # 80000000 (-0.0) is constantly used for capacities in arrays so we also exclude it
    if (v & 0x7fffffff) == 0: return allow_zero

    exp = ((v & 0x7f800000) >> 23) - 127
    # mant = v & 0x007fffff

    if not -30 < exp < 30: return False
    # if (mant & 0x0000ffff) == 0: return True

    return True

# def find_float_vectors():
def all_bytes(f, ea, size):
    return all(map(lambda off: f(ea + off), range(0, size)))

def all_of_v4(f, ea):
    return all(map(lambda off: f(ea + off), range(0, 16, 4)))

def isunk(ea):
    return is_unknown(get_flags(ea))

def may_convert_to_float(ea):
    return calc_max_align(ea) >= 4 and all_bytes(isunk, ea, 4) or is_dword(get_flags(ea))

def may_convert_to_v4(ea):
    return calc_max_align(ea) >= 2 and all_bytes(isunk, ea, 16) or is_oword(get_flags(ea))

def find_common_math_objects():
    seg = get_segm_by_name(rdata_seg)

    print(f'info: searching for vectors in segment {rdata_seg}')
    match_bytes(seg, commonvectors, v4_tif, 4)

    print(f'info: searching for quaternions in segment {rdata_seg}')
    match_bytes(seg, commonquats, quat_tif, 4)

    print(f'info: searching for matrices in segment {rdata_seg}')
    match_bytes(seg, commonmats, mat44_tif, 4)

    print(f'info: searching for float arrays in segment {rdata_seg}')
    match_bytes(seg, commonfloatarrays, float_tif, 2, True)

    print(f'info: searching for origin vectors in segment {rdata_seg}')
    for ea in binsearch_matches(seg.start_ea, seg.end_ea, originvec, None, 4):
        flags = get_flags(ea)
        prev_ea = ea - 16
        next_ea = ea + 16

        if (is_unknown(flags) or is_oword(flags)) and prev_ea >= seg.start_ea and next_ea <= seg.end_ea - 16 and idc_guess_type(prev_ea) in ('V4', 'float', 'csl::math::Vector4', 'csl::math::Matrix44', 'csl::math::Quaternion') and idc_guess_type(next_ea) in ('V4', 'csl::math::Vector4', 'csl::math::Matrix44', 'csl::math::Quaternion'):
            # We're in a math block, so we'll accept this as an origin vector
            force_apply_tinfo(ea, v4_tif, TINFO_GUESSED)
            set_cmt(ea, 'origin xyzw', True)

    print(f'info: searching for probable standalone floats in segment {rdata_seg}')
    for ea in not_tails(seg.start_ea, seg.end_ea):
        if ea <= seg.end_ea - 16 and may_convert_to_v4(ea) and all_of_v4(lambda ea: looks_like_float(get_dword(ea), True), ea) and not all_of_v4(lambda ea: get_dword(ea) == 0, ea):
            force_apply_tinfo(ea, v4_tif, TINFO_GUESSED)
        elif ea <= seg.end_ea - 4 and may_convert_to_float(ea) and looks_like_float(get_dword(ea)):
            force_apply_tinfo(ea, float_tif, TINFO_GUESSED)

    print(f'info: searching for special floats in segment {rdata_seg}')
    match_bytes(seg, { k: numbers[k] for k in numbers if not numbers[k].startswith(b'\x00\x00') }, float_tif, 2)
