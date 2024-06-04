import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from rangers_analysis.informed_analysis.report import clear_report, print_report
from rangers_analysis.informed_analysis.standard_analysis import run_standard_analysis
from rangers_analysis.informed_analysis.extensive_analysis import run_extensive_analysis

clear_report()
run_standard_analysis()
run_extensive_analysis()
print_report()
