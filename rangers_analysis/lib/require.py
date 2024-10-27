from .analysis_exceptions import AnalysisException

class NotFoundException(AnalysisException):
    pass

def require(Err, x, *err_args, **kwargs):
    if x == None:
        raise Err(*err_args)
    return kwargs['retval'] if 'retval' in kwargs else x

def require_wrap(Err, f):
    return lambda *args: require(Err, f(*args), *args)
