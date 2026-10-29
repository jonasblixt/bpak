#include <stdio.h>
/* Python 3.10 and newer must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include <bpak/crypto.h>

#include "module.h"

static PyObject *log_func = Py_None;

int bpak_printf(int verbosity, const char *fmt, ...)
{
    char log_buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(log_buf, sizeof(log_buf), fmt, args);
    va_end(args);

    if (log_func != Py_None) {
        /* Messages contain file names, which need not be UTF-8 */
        PyObject *message =
            PyUnicode_DecodeUTF8(log_buf, strlen(log_buf), "backslashreplace");
        PyObject *result = NULL;

        if (message != NULL) {
            result =
                PyObject_CallFunction(log_func, "(iN)", verbosity, message);
        }

        /* The library continues after logging, an exception left set here
         * surfaces later as a SystemError */
        if (result == NULL) {
            PyErr_WriteUnraisable(log_func);
        }

        Py_XDECREF(result);
    }

    return BPAK_OK;
}

int py_to_uint(PyObject *value,
               unsigned long long max,
               const char *name,
               unsigned long long *out)
{
    unsigned long long result;

    if (value == NULL) {
        PyErr_Format(PyExc_TypeError, "cannot delete %s", name);
        return -1;
    }

    if (!PyLong_Check(value)) {
        PyErr_Format(PyExc_TypeError,
                     "%s must be an int, not %.200s",
                     name,
                     Py_TYPE(value)->tp_name);
        return -1;
    }

    result = PyLong_AsUnsignedLongLong(value);
    if (result == (unsigned long long)-1 && PyErr_Occurred()) {
        if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
            goto out_of_range;
        }
        return -1;
    }

    if (result > max) {
        goto out_of_range;
    }

    *out = result;
    return 0;

out_of_range:
    PyErr_Clear();
    PyErr_Format(PyExc_OverflowError,
                 "%s must be between 0 and %llu",
                 name,
                 max);
    return -1;
}

/* MODULE DEFINITION */
static PyObject *m_generate_id(PyObject *module, PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"string", NULL};
    char *input_string = NULL;
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "s:id", kwlist, &input_string);
    if (!rc) {
        return NULL;
    }

    return PyLong_FromUnsignedLong(bpak_id(input_string));
}

static PyObject *m_set_log_func(PyObject *module, PyObject *args,
                                PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"log_func", NULL};
    PyObject *func = NULL;
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &func);
    if (!rc) {
        return NULL;
    }

    /* Keep a reference, the callback may otherwise be garbage collected */
    Py_INCREF(func);
    if (log_func != Py_None)
        Py_DECREF(log_func);
    log_func = func;

    Py_RETURN_NONE;
}

/* O& converter for an optional package, None is no package */
static int convert_optional_package(PyObject *obj, void *result)
{
    BPAKPackage **package = result;

    if (obj == Py_None) {
        *package = NULL;
        return 1;
    }

    if (!PyObject_TypeCheck(obj, &BPAKPackageType)) {
        PyErr_Format(PyExc_TypeError,
                     "origin must be bpak.Package or None, not %.200s",
                     Py_TYPE(obj)->tp_name);
        return 0;
    }

    *package = (BPAKPackage *)obj;
    return 1;
}

typedef int (*transport_func)(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin);

static PyObject *transport(PyObject *args,
                           PyObject *kwds,
                           const char *format,
                           transport_func func,
                           const char *error)
{
    int rc;
    static char *kwlist[] = { "input", "output", "origin", NULL };
    BPAKPackage *input = NULL;
    BPAKPackage *origin = NULL;
    BPAKPackage *output = NULL;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     format,
                                     kwlist,
                                     &BPAKPackageType,
                                     &input,
                                     &BPAKPackageType,
                                     &output,
                                     convert_optional_package,
                                     &origin);
    if (!rc) {
        return NULL;
    }

    if (package_check_open(input) < 0 || package_check_open(output) < 0 ||
        (origin && package_check_open(origin) < 0)) {
        return NULL;
    }

    rc = func(&input->pkg, &output->pkg, origin ? &origin->pkg : NULL);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "%s", error);
    }

    Py_RETURN_NONE;
}

static PyObject *m_transport_encode(PyObject *Py_UNUSED(module),
                                    PyObject *args,
                                    PyObject *kwds)
{
    return transport(args,
                     kwds,
                     "O!O!|O&:transport_encode",
                     bpak_pkg_transport_encode,
                     "Transport encoding failed");
}

static PyObject *m_transport_decode(PyObject *Py_UNUSED(module),
                                    PyObject *args,
                                    PyObject *kwds)
{
    return transport(args,
                     kwds,
                     "O!O!|O&:transport_decode",
                     bpak_pkg_transport_decode,
                     "Transport decoding failed");
}

static PyObject *m_version(PyObject *module, PyObject *Py_UNUSED(args))
{
    (void)module;

    return PyUnicode_FromString(bpak_version());
}

static PyObject *m_id_to_string(PyObject *module, PyObject *args,
                                PyObject *kwds)
{
    int rc;
    static char *kwlist[] = { "id", NULL };
    bpak_id_t id;
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "I:id_to_string", kwlist, &id);
    if (!rc) {
        return NULL;
    }

    return PyUnicode_FromString(bpak_id_to_string(id));
}

static PyObject *m_hash_kind_to_string(PyObject *module, PyObject *args,
                                       PyObject *kwds)
{
    int rc;
    static char *kwlist[] = { "kind", NULL };
    unsigned char kind;
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "b:hash_kind_to_string",
                                     kwlist,
                                     &kind);
    if (!rc) {
        return NULL;
    }

    return PyUnicode_FromString(bpak_hash_kind(kind));
}

static PyObject *m_signature_kind_to_string(PyObject *module, PyObject *args,
                                            PyObject *kwds)
{
    int rc;
    static char *kwlist[] = { "kind", NULL };
    unsigned char kind;
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "b:signature_kind_to_string",
                                     kwlist,
                                     &kind);
    if (!rc) {
        return NULL;
    }

    return PyUnicode_FromString(bpak_signature_kind(kind));
}

static PyObject *m_parse_public_key(PyObject *module, PyObject *args,
                                    PyObject *kwds)
{
    int rc;
    static char *kwlist[] = { "data", NULL };
    const char *data;
    Py_ssize_t size;
    struct bpak_key *key = NULL;
    PyObject *result;
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "y#:parse_public_key",
                                     kwlist,
                                     &data,
                                     &size);
    if (!rc) {
        return NULL;
    }

    rc = bpak_crypto_parse_public_key((const uint8_t *)data, size, &key);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "Could not parse key");
    }

    result =
        Py_BuildValue("(iy#)", key->kind, key->data, (Py_ssize_t)key->size);
    bpak_free(key);
    return result;
}

static PyMethodDef module_methods[] = {
    { "version",
      (PyCFunction)(void (*)(void))m_version,
      METH_NOARGS,
      "Version of the bpak library" },

    { "id_to_string",
      (PyCFunction)(void (*)(void))m_id_to_string,
      METH_VARARGS | METH_KEYWORDS,
      "Name of a well known bpak id, or an empty string" },

    { "hash_kind_to_string",
      (PyCFunction)(void (*)(void))m_hash_kind_to_string,
      METH_VARARGS | METH_KEYWORDS,
      "Name of a hash kind (one of HASH_ constants)" },

    { "signature_kind_to_string",
      (PyCFunction)(void (*)(void))m_signature_kind_to_string,
      METH_VARARGS | METH_KEYWORDS,
      "Name of a signature kind (one of SIGN_ constants)" },

    { "parse_public_key",
      (PyCFunction)(void (*)(void))m_parse_public_key,
      METH_VARARGS | METH_KEYWORDS,
      "Parse a DER encoded public key, returns (KEY_ kind, DER data)" },

    { "id",
      (PyCFunction)(void (*)(void))m_generate_id,
      METH_VARARGS | METH_KEYWORDS,
      "Convert string to bpak id" },

    { "set_log_func",
      (PyCFunction)(void (*)(void))m_set_log_func,
      METH_VARARGS | METH_KEYWORDS,
      "Set logging function callback" },

    { "transport_encode",
      (PyCFunction)(void (*)(void))m_transport_encode,
      METH_VARARGS | METH_KEYWORDS,
      "Transport encode from input to output, using origin for diff origin" },

    { "transport_decode",
      (PyCFunction)(void (*)(void))m_transport_decode,
      METH_VARARGS | METH_KEYWORDS,
      "Transport decode from input to output, using origin for diff origin" },

    { NULL }
};

static PyModuleDef module = { PyModuleDef_HEAD_INIT,
                              .m_name = "bpak._bpak",
                              .m_doc = NULL,
                              .m_size = -1,
                              .m_methods = module_methods };

#define INT_CONSTANT(name) { #name, BPAK_##name }

static const struct {
    const char *name;
    long value;
} int_constants[] = {
    INT_CONSTANT(HASH_SHA256),
    INT_CONSTANT(HASH_SHA384),
    INT_CONSTANT(HASH_SHA512),

    INT_CONSTANT(SIGN_RSA4096),
    INT_CONSTANT(SIGN_PRIME256v1),
    INT_CONSTANT(SIGN_SECP384r1),
    INT_CONSTANT(SIGN_SECP521r1),

    INT_CONSTANT(KEY_PUB_RSA4096),
    INT_CONSTANT(KEY_PUB_PRIME256v1),
    INT_CONSTANT(KEY_PUB_SECP384r1),
    INT_CONSTANT(KEY_PUB_SECP521r1),

    INT_CONSTANT(FLAG_EXCLUDE_FROM_HASH),
    INT_CONSTANT(FLAG_TRANSPORT),

    INT_CONSTANT(METADATA_BYTES),
    INT_CONSTANT(SIGNATURE_MAX_BYTES),
};

PyMODINIT_FUNC PyInit__bpak(void)
{
    /* PyModule_AddType adds the types by the name after the last dot of
     * tp_name, bpak.Package is _bpak.Package */
    PyTypeObject *types[] = { &BPAKPackageType, &BPAKPartType, &BPAKMetaType };
    PyObject *m_p;

    m_p = PyModule_Create(&module);
    if (m_p == NULL) {
        return NULL;
    }

    if (bpak_exceptions_init(m_p) < 0) {
        goto err_out;
    }

    for (unsigned int i = 0; i < membersof(types); i++) {
        if (PyModule_AddType(m_p, types[i]) < 0) {
            goto err_out;
        }
    }

    for (unsigned int i = 0; i < membersof(int_constants); i++) {
        if (PyModule_AddIntConstant(m_p,
                                    int_constants[i].name,
                                    int_constants[i].value) < 0) {
            goto err_out;
        }
    }

    return m_p;

err_out:
    Py_DECREF(m_p);
    return NULL;
}
