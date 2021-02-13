try:
    # It's not possible to include the C extension when building
    #  readthedocs.io documentation. And it's not needed for generating
    # the documentation.
    import _bpak
except:
    print("Warning: Could not import bpak C extension")

def id(input_string):
    """Converts a text string to a BPAK ID"""
    return _bpak.id(input_string)

def set_log_function(log_func):
    """Set a logging call back. The log function should have two arguments:
        my_log_func(level, message)"""
    _bpak.set_log_func(log_func)
