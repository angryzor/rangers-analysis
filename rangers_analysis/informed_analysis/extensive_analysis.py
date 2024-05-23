from rangers_analysis.informed_analysis.static_initializers import find_static_initializers
from rangers_analysis.informed_analysis.math_objects import find_common_math_objects
from rangers_analysis.informed_analysis.ctors_and_dtors import find_ctors_and_dtors

def run_extensive_analysis():
    static_initializer_eas = find_static_initializers()

    print('=== FLOATING POINT MATH OBJECT ANALYSIS ===')
    find_common_math_objects(static_initializer_eas)
    print('=== VTABLE BASED CTOR/DTOR ANALYSIS ===')
    find_ctors_and_dtors()
