import _bpak

def id(input_string):
    """Converts a text string to a BPAK ID"""
    return _bpak.id(input_string)

def set_log_function(log_func):
    """Set a logging call back. The log function should have two arguments:
        my_log_func(level, message)"""
    _bpak.set_log_func(log_func)

class Package(_bpak.Package):
    def __init__(self, filename, mode):
        self.pkg = _bpak.Package(filename, mode)
    def id(self):
        return self.pkg.id()
    def __str__(self):
        return "Blerp"
