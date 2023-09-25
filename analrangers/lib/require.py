from .analysis_exceptions import AnalException

class NotFoundException(AnalException):
    pass

def require(Err, x, *err_args, **kwargs):
    if not x:
        raise Err(*err_args)
    return kwargs['retval'] if 'retval' in kwargs else x

def require_wrap(Err, f):
    return lambda *args: require(Err, f(*args), *args)
