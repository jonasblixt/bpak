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

#include "python_wrapper.h"

static PyObject *log_func = Py_None;

int bpak_printf(int verbosity, const char *fmt, ...)
{
    char log_buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(log_buf, sizeof(log_buf), fmt, args);
    va_end(args);

    if (log_func != Py_None) {
        Py_XDECREF(PyObject_CallFunction(log_func, "(is)", verbosity, log_buf));
    }

    return BPAK_OK;
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

    return PyLong_FromLong(bpak_id(input_string));
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

static PyObject *m_transport_encode(PyObject *self, PyObject *args,
                                    PyObject *kwds)
{
    (void)self;
    int rc;
    static char *kwlist[] = {"input", "output", "origin", NULL};
    BPAKPackage *input = NULL;
    BPAKPackage *origin = NULL;
    BPAKPackage *output = NULL;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "O!O!|O!:transport_encode",
                                     kwlist,
                                     &BPAKPackageType,
                                     &input,
                                     &BPAKPackageType,
                                     &output,
                                     &BPAKPackageType,
                                     &origin);
    if (!rc) {
        return NULL;
    }

    if (package_check_open(input) < 0 || package_check_open(output) < 0 ||
        (origin && package_check_open(origin) < 0)) {
        return NULL;
    }

    rc = bpak_pkg_transport_encode(&input->pkg,
                                   &output->pkg,
                                   origin ? &origin->pkg : NULL);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "Transport encoding failed");
    }

    Py_RETURN_NONE;
}

static PyObject *m_transport_decode(PyObject *self, PyObject *args,
                                          PyObject *kwds)
{
    (void)self;
    int rc;
    static char *kwlist[] = {"input", "output", "origin", NULL};
    BPAKPackage *input = NULL;
    BPAKPackage *origin = NULL;
    BPAKPackage *output = NULL;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "O!O!|O!:transport_decode",
                                     kwlist,
                                     &BPAKPackageType,
                                     &input,
                                     &BPAKPackageType,
                                     &output,
                                     &BPAKPackageType,
                                     &origin);
    if (!rc) {
        return NULL;
    }

    if (package_check_open(input) < 0 || package_check_open(output) < 0 ||
        (origin && package_check_open(origin) < 0)) {
        return NULL;
    }

    rc = bpak_pkg_transport_decode(&input->pkg,
                                   &output->pkg,
                                   origin ? &origin->pkg : NULL);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "Transport decoding failed");
    }

    Py_RETURN_NONE;
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
    free(key);
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

PyMODINIT_FUNC PyInit__bpak(void)
{
    PyObject *m_p;

    if (PyType_Ready(&BPAKPackageType) < 0)
        return NULL;
    if (PyType_Ready(&BPAKPartType) < 0)
        return NULL;
    if (PyType_Ready(&BPAKMetaType) < 0)
        return NULL;

    /* Module creation. */
    m_p = PyModule_Create(&module);

    if (m_p == NULL) {
        return NULL;
    }

    if (bpak_exceptions_init(m_p) < 0) {
        Py_DECREF(m_p);
        return NULL;
    }

    Py_INCREF(&BPAKPackageType);
    if (PyModule_AddObject(m_p, "Package", (PyObject *)&BPAKPackageType) < 0) {
        Py_DECREF(&BPAKPackageType);
        Py_DECREF(m_p);
        return NULL;
    }

    Py_INCREF(&BPAKPartType);
    if (PyModule_AddObject(m_p, "Part", (PyObject *)&BPAKPartType) < 0) {
        Py_DECREF(&BPAKPartType);
        Py_DECREF(m_p);
        return NULL;
    }

    Py_INCREF(&BPAKMetaType);
    if (PyModule_AddObject(m_p, "Meta", (PyObject *)&BPAKMetaType) < 0) {
        Py_DECREF(&BPAKMetaType);
        Py_DECREF(m_p);
        return NULL;
    }

    PyModule_AddIntConstant(m_p, "HASH_SHA256", BPAK_HASH_SHA256);
    PyModule_AddIntConstant(m_p, "HASH_SHA384", BPAK_HASH_SHA384);
    PyModule_AddIntConstant(m_p, "HASH_SHA512", BPAK_HASH_SHA512);

    PyModule_AddIntConstant(m_p, "SIGN_RSA4096", BPAK_SIGN_RSA4096);
    PyModule_AddIntConstant(m_p, "SIGN_PRIME256v1", BPAK_SIGN_PRIME256v1);
    PyModule_AddIntConstant(m_p, "SIGN_SECP384r1", BPAK_SIGN_SECP384r1);
    PyModule_AddIntConstant(m_p, "SIGN_SECP521r1", BPAK_SIGN_SECP521r1);

    PyModule_AddIntConstant(m_p, "KEY_PUB_RSA4096", BPAK_KEY_PUB_RSA4096);
    PyModule_AddIntConstant(m_p, "KEY_PUB_PRIME256v1", BPAK_KEY_PUB_PRIME256v1);
    PyModule_AddIntConstant(m_p, "KEY_PUB_SECP384r1", BPAK_KEY_PUB_SECP384r1);
    PyModule_AddIntConstant(m_p, "KEY_PUB_SECP521r1", BPAK_KEY_PUB_SECP521r1);

    PyModule_AddIntConstant(m_p,
                            "FLAG_EXCLUDE_FROM_HASH",
                            BPAK_FLAG_EXCLUDE_FROM_HASH);
    PyModule_AddIntConstant(m_p, "FLAG_TRANSPORT", BPAK_FLAG_TRANSPORT);

    PyModule_AddIntConstant(m_p, "METADATA_BYTES", BPAK_METADATA_BYTES);
    PyModule_AddIntConstant(m_p,
                            "SIGNATURE_MAX_BYTES",
                            BPAK_SIGNATURE_MAX_BYTES);
    return (m_p);
}
