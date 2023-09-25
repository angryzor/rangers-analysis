from analrangers.lib.analysis_exceptions import AnalException

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
    except AnalException as e:
        report_failure(str(e))
