from rangers_analysis.lib.analysis_exceptions import AnalysisException

manual = []

def clear_report():
    manual.clear()

def print_report():
    print('Some issues need manual attention:')
    for x in manual:
        print(x)

def report_failure(s):
    print(f'error: {s}')
    manual.append(s)

def handle_anal_exceptions(f):
    try:
        f()
    except AnalysisException as e:
        report_failure(str(e))
