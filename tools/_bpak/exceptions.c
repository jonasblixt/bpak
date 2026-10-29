/* Python 3.10 and newer must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdarg.h>
#include <bpak/bpak.h>

#include "module.h"

PyObject *BPAKPackageError;

/* One exception class per 'enum bpak_errors' value. The classes are named
 * after the enum and carry the error code in the class attribute 'code'. */
static const char *exception_names[] = {
    [BPAK_FAILED] = "FailedError",
    [BPAK_NOT_FOUND] = "NotFoundError",
    [BPAK_SIZE_ERROR] = "SizeError",
    [BPAK_NO_SPACE_LEFT] = "NoSpaceLeftError",
    [BPAK_BAD_ALIGNMENT] = "BadAlignmentError",
    [BPAK_SEEK_ERROR] = "SeekError",
    [BPAK_NOT_SUPPORTED] = "NotSupportedError",
    [BPAK_NEEDS_MORE_DATA] = "NeedsMoreDataError",
    [BPAK_WRITE_ERROR] = "WriteError",
    [BPAK_DECOMPRESSOR_ERROR] = "DecompressorError",
    [BPAK_COMPRESSOR_ERROR] = "CompressorError",
    [BPAK_PATCH_READ_ORIGIN_ERROR] = "PatchReadOriginError",
    [BPAK_PATCH_WRITE_ERROR] = "PatchWriteError",
    [BPAK_READ_ERROR] = "ReadError",
    [BPAK_BAD_MAGIC] = "BadMagicError",
    [BPAK_UNSUPPORTED_HASH_ALG] = "UnsupportedHashAlgError",
    [BPAK_BUFFER_TOO_SMALL] = "BufferTooSmallError",
    [BPAK_FILE_NOT_FOUND] = "FileNotFoundError",
    [BPAK_KEY_DECODE] = "KeyDecodeError",
    [BPAK_VERIFY_FAIL] = "VerifyFailError",
    [BPAK_SIGN_FAIL] = "SignFailError",
    [BPAK_UNSUPPORTED_KEY] = "UnsupportedKeyError",
    [BPAK_BAD_ROOT_HASH] = "BadRootHashError",
    [BPAK_BAD_PAYLOAD_HASH] = "BadPayloadHashError",
    [BPAK_MISSING_META_DATA] = "MissingMetaDataError",
    [BPAK_PACKAGE_UUID_MISMATCH] = "PackageUuidMismatchError",
    [BPAK_UNSUPPORTED_COMPRESSION] = "UnsupportedCompressionError",
    [BPAK_KEY_NOT_FOUND] = "KeyNotFoundError",
    [BPAK_KEYSTORE_ID_MISMATCH] = "KeystoreIdMismatchError",
    [BPAK_EXISTS] = "ExistsError",
};

static PyObject *exceptions[membersof(exception_names)];

static PyObject *new_exception(const char *name, PyObject *base, int code)
{
    char qualified_name[64];
    PyObject *dict;
    PyObject *code_obj;
    PyObject *exc;

    dict = PyDict_New();
    if (dict == NULL)
        return NULL;

    code_obj = PyLong_FromLong(code);
    if (code_obj == NULL || PyDict_SetItemString(dict, "code", code_obj) < 0) {
        Py_XDECREF(code_obj);
        Py_DECREF(dict);
        return NULL;
    }
    Py_DECREF(code_obj);

    snprintf(qualified_name, sizeof(qualified_name), "bpak.%s", name);
    exc = PyErr_NewException(qualified_name, base, dict);
    Py_DECREF(dict);
    return exc;
}

int bpak_exceptions_init(PyObject *module)
{
    /* The module and the variables here hold a reference each */
    BPAKPackageError = new_exception("Error", NULL, BPAK_FAILED);
    if (BPAKPackageError == NULL ||
        PyModule_AddObjectRef(module, "Error", BPAKPackageError) < 0) {
        return -1;
    }

    for (unsigned int i = 0; i < membersof(exception_names); i++) {
        const char *name = exception_names[i];

        if (name == NULL)
            continue;

        exceptions[i] = new_exception(name, BPAKPackageError, i);
        if (exceptions[i] == NULL ||
            PyModule_AddObjectRef(module, name, exceptions[i]) < 0) {
            return -1;
        }
    }

    return 0;
}

PyObject *bpak_raise(int rc, const char *fmt, ...)
{
    PyObject *exc = BPAKPackageError;
    PyObject *message;
    va_list args;

    if (-rc > 0 && -rc < (int)membersof(exceptions) && exceptions[-rc] != NULL)
        exc = exceptions[-rc];

    va_start(args, fmt);
    message = PyUnicode_FromFormatV(fmt, args);
    va_end(args);

    if (message == NULL)
        return NULL;

    PyErr_Format(exc, "%U: %s", message, bpak_error_string(rc));
    Py_DECREF(message);
    return NULL;
}
