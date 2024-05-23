import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import configure_rangers_analysis
from configurations import configs

configure_rangers_analysis(configs['wars']['latest'])

from rangers_analysis.informed_analysis.static_initializers import find_static_initializers
from rangers_analysis.informed_analysis.services import find_services
from rangers_analysis.informed_analysis.rfl import find_rfl_statics
from rangers_analysis.informed_analysis.gocs import find_gocs
from rangers_analysis.informed_analysis.managed_resources import find_managed_resources
from rangers_analysis.informed_analysis.object_classes import find_obj_classes
from rangers_analysis.informed_analysis.obj_infos import find_obj_infos
from rangers_analysis.informed_analysis.state_descs import find_state_descs
from rangers_analysis.informed_analysis.math_objects import find_common_math_objects
from rangers_analysis.informed_analysis.singletons import find_singletons
from rangers_analysis.informed_analysis.ctors_and_dtors import find_ctors_and_dtors
from rangers_analysis.informed_analysis.report import clear_report, print_report

clear_report()

static_initializer_eas = find_static_initializers()

print('=== SERVICE ANALYSIS ===')
find_services()
print('=== REFLECTION ANALYSIS ===')
find_rfl_statics(static_initializer_eas)
print('=== GOC ANALYSIS ===')
find_gocs()
print('=== GAMEOBJECT ANALYSIS ===')
find_obj_classes()
print('=== OBJINFO ANALYSIS ===')
find_obj_infos()
print('=== STATEDESC ANALYSIS ===')
find_state_descs(static_initializer_eas)
print('=== MANAGED RESOURCE ANALYSIS ===')
find_managed_resources()
print('=== SINGLETON ANALYSIS ===')
find_singletons(static_initializer_eas)
# print('=== FLOATING POINT MATH OBJECT ANALYSIS ===')
# find_common_math_objects(static_initializer_eas)
# print('=== VTABLE BASED CTOR/DTOR ANALYSIS ===')
# find_ctors_and_dtors()

print_report()
