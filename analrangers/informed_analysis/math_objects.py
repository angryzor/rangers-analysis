from ida_bytes import set_cmt, get_bytes, is_unknown, is_oword, get_flags
from ida_segment import get_segm_by_name
from ida_typeinf import apply_tinfo, TINFO_GUESSED, idc_guess_type
from analrangers.lib.util import require_type, binsearch_matches
from .report import handle_anal_exceptions
from ctypes import cast, pointer, c_long, c_float, POINTER

quat_tif = require_type('csl::math::Quaternion')
v4_tif = require_type('csl::math::Vector4')
mat44_tif = require_type('csl::math::Matrix44')


numbers = {
    '0': b'\x00\x00\x00\x00',
    '1': b'\x00\x00\x80\x3F',
    '-1': b'\x00\x00\x80\xBF',
    'pi': b'\xDB\x0F\x49\x40',
    'tau': b'\xDB\x0F\xC9\x40',
    'pi / 2': b'\xDB\x0F\xC9\x3F',
    '1 / tau': b'\x83\xF9\x22\x3E',
    'nan': b'\x00\x00\xC0\x7F',
    'floatprecision': b'\x00\x00\x00\x34',
}

masks = {
    'none': b'\x00\x00\x00\x00',
    'exp': b'\x00\x00\x80\x7F',
    'abs': b'\xFF\xFF\xFF\x7F',
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
    'mirror over origin': numbers['-1'] + numbers['-1'] + numbers['-1'] + numbers['1'],

    'unit xyz': numbers['1'] + numbers['1'] + numbers['1'] + numbers['0'],
    'unit xyzw': numbers['1'] + numbers['1'] + numbers['1'] + numbers['1'],
    'negative unit xyz': numbers['-1'] + numbers['-1'] + numbers['-1'] + numbers['0'],
    'negative unit xyzw': numbers['-1'] + numbers['-1'] + numbers['-1'] + numbers['-1'],
    
    'mask all xyzw': masks['all'] + masks['all'] + masks['all'] + masks['all'],
    'mask abs xyzw': masks['abs'] + masks['abs'] + masks['abs'] + masks['abs'],
    'mask exp xyzw': masks['exp'] + masks['exp'] + masks['exp'] + masks['exp'],
    'mask unknown xyzw': masks['unknown'] + masks['unknown'] + masks['unknown'] + masks['unknown'],
    'mask all xyz': masks['all'] + masks['all'] + masks['all'] + masks['none'],
    'mask abs xyz': masks['abs'] + masks['abs'] + masks['abs'] + masks['none'],
    'mask exp xyz': masks['exp'] + masks['exp'] + masks['exp'] + masks['none'],
    
    'quaternion multtable i': numbers['1'] + numbers['-1'] + numbers['1'] + numbers['-1'],
    'quaternion multtable j': numbers['1'] + numbers['1'] + numbers['-1'] + numbers['-1'],
    'quaternion multtable k': numbers['-1'] + numbers['1'] + numbers['1'] + numbers['-1'],

    'pi xyzw': numbers['pi'] + numbers['pi'] + numbers['pi'] + numbers['pi'],
    'tau xyzw': numbers['tau'] + numbers['tau'] + numbers['tau'] + numbers['tau'],
    'pi / 2 xyzw': numbers['pi / 2'] + numbers['pi / 2'] + numbers['pi / 2'] + numbers['pi / 2'],
    '1 / tau xyzw': numbers['1 / tau'] + numbers['1 / tau'] + numbers['1 / tau'] + numbers['1 / tau'],
    'nan xyzw': numbers['nan'] + numbers['nan'] + numbers['nan'] + numbers['nan'],
    'floatprecision xyzw': numbers['floatprecision'] + numbers['floatprecision'] + numbers['floatprecision'] + numbers['floatprecision'],
}

commonquats = {
    'unit quaternion': numbers['0'] + numbers['0'] + numbers['0'] + numbers['1'],
}

commonmats = {
    'identity': commonvectors['basis x'] + commonvectors['basis y'] + commonvectors['basis z'] + commonquats['unit quaternion']
}

def match_bytes(seg, d, tif, align):
    for k in d:
        print(f'info: finding matches for `{k}`')
        for ea in binsearch_matches(seg.start_ea, seg.end_ea, d[k], None, align):
            flags = get_flags(ea)
            typ = idc_guess_type(ea)
            typ = typ and typ.split('[')[0]

            if is_unknown(flags) or is_oword(flags) or typ in ('V4', 'csl::math::Vector4', 'csl::math::Matrix44', 'csl::math::Quaternion'):
                print(f'info: found `{k}` instance at {ea:x}')

                apply_tinfo(ea, tif, TINFO_GUESSED)
                set_cmt(ea, k, True)

def looks_like_float(v):
    # 80000000 is constantly used for capacities in arrays so we also exclude it
    if (v & 0x7fffffff) == 0: return False

    exp = ((v & 0x7f800000) >> 23) - 127
    mant = v & 0x007fffff

    if not -30 < exp < 30: return False
    if not (mant & 0x0000ffff) == 0: return False

    return True

# def find_float_vectors():


def find_common_math_objects():
    seg_name = '.xdata'
    seg = get_segm_by_name(seg_name)

    print(f'info: searching for vectors in segment {seg_name}')
    match_bytes(seg, commonvectors, v4_tif, 4)

    print(f'info: searching for quaternions in segment {seg_name}')
    match_bytes(seg, commonquats, quat_tif, 4)

    print(f'info: searching for matrices in segment {seg_name}')
    match_bytes(seg, commonmats, mat44_tif, 4)

    for ea in binsearch_matches(seg.start_ea, seg.end_ea, originvec, None, 4):
        flags = get_flags(ea)
        prev_ea = ea - 16
        next_ea = ea + 16

        if (is_unknown(flags) or is_oword(flags)) and prev_ea >= seg.start_ea and next_ea <= seg.end_ea - 16 and idc_guess_type(prev_ea) in ('V4', 'csl::math::Vector4', 'csl::math::Matrix44', 'csl::math::Quaternion') and idc_guess_type(next_ea) in ('V4', 'csl::math::Vector4', 'csl::math::Matrix44', 'csl::math::Quaternion'):
            # We're in a math block, so we'll accept this as an origin vector
            apply_tinfo(ea, v4_tif, TINFO_GUESSED)
            set_cmt(ea, 'origin xyzw', True)
