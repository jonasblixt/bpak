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
#include <bpak/key.h>

#include "python_wrapper.h"

PyObject *BPAKPackageError;
static PyObject *log_func = Py_None;

int bpak_printf(int verbosity, const char *fmt, ...)
{
    char log_buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(log_buf, sizeof(log_buf), fmt, args);
    va_end(args);

    if (log_func != Py_None) {
        PyObject_CallFunction(log_func, "(is)", verbosity, log_buf);
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
    (void)module;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &log_func);
    if (!rc) {
        return NULL;
    }

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

    rc = bpak_pkg_transport_encode(&input->pkg,
                                   &output->pkg,
                                   origin ? &origin->pkg : NULL);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError,
            "Transport encoding failed: %s", bpak_error_string(rc));
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

    rc = bpak_pkg_transport_decode(&input->pkg,
                                   &output->pkg,
                                   origin ? &origin->pkg : NULL);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError,
            "Transport decoding failed: %s", bpak_error_string(rc));
    }

    Py_RETURN_NONE;
}


static PyObject *m_hash_kind_str(PyObject *module, PyObject *args,
                                 PyObject *kwds)
{
    (void)module;
    int rc;
    static char *kwlist[] = {"kind", NULL};
    unsigned int kind;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "I:hash_kind_str", kwlist,
                                     &kind);
    if (!rc) {
        return NULL;
    }

    const char *s = bpak_hash_kind((uint8_t)kind);
    return PyUnicode_FromString(s);
}

static PyObject *m_signature_kind_str(PyObject *module, PyObject *args,
                                      PyObject *kwds)
{
    (void)module;
    int rc;
    static char *kwlist[] = {"kind", NULL};
    unsigned int kind;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "I:signature_kind_str",
                                     kwlist, &kind);
    if (!rc) {
        return NULL;
    }

    const char *s = bpak_signature_kind((uint8_t)kind);
    return PyUnicode_FromString(s);
}

static PyObject *m_id_to_string(PyObject *module, PyObject *args,
                                PyObject *kwds)
{
    (void)module;
    int rc;
    static char *kwlist[] = {"id", NULL};
    unsigned int id;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "I:id_to_string", kwlist,
                                     &id);
    if (!rc) {
        return NULL;
    }

    const char *s = bpak_id_to_string((bpak_id_t)id);
    if (s == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(s);
}

static PyObject *m_meta_to_string(PyObject *module, PyObject *args,
                                  PyObject *kwds)
{
    (void)module;
    int rc;
    static char *kwlist[] = {"package", "meta", NULL};
    BPAKPackage *package = NULL;
    BPAKMeta *meta_obj = NULL;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "O!O!:meta_to_string",
                                     kwlist,
                                     &BPAKPackageType, &package,
                                     &BPAKMetaType, &meta_obj);
    if (!rc) {
        return NULL;
    }

    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    struct bpak_meta_header *m;

    rc = bpak_get_meta(h, meta_obj->meta_id, meta_obj->part_ref, &m);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get meta: %s",
                            bpak_error_string(rc));
    }

    char buf[256];
    rc = bpak_meta_to_string(h, m, buf, sizeof(buf));
    if (rc != BPAK_OK) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(buf);
}

static PyObject *m_add_transport_meta(PyObject *module, PyObject *args,
                                      PyObject *kwds)
{
    (void)module;
    int rc;
    static char *kwlist[] = {"package", "part_id", "encoder_id", "decoder_id",
                             NULL};
    BPAKPackage *package = NULL;
    unsigned int part_id;
    unsigned int encoder_id;
    unsigned int decoder_id;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "O!III:add_transport_meta",
                                     kwlist,
                                     &BPAKPackageType, &package,
                                     &part_id, &encoder_id, &decoder_id);
    if (!rc) {
        return NULL;
    }

    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    rc = bpak_add_transport_meta(h, (bpak_id_t)part_id,
                                 (uint32_t)encoder_id, (uint32_t)decoder_id);
    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError,
                            "failed to add transport metadata: %s",
                            bpak_error_string(rc));
    }

    rc = package_write_header(package, false);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_IOError, "could not write header: %s",
                            bpak_error_string(rc));
    }

    Py_RETURN_NONE;
}

static PyObject *m_parse_public_key(PyObject *module, PyObject *args,
                                    PyObject *kwds)
{
    (void)module;
    int rc;
    static char *kwlist[] = {"data", NULL};
    const uint8_t *buffer;
    Py_ssize_t length;
    struct bpak_key *key = NULL;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "y#:parse_public_key",
                                     kwlist, &buffer, &length);
    if (!rc) {
        return NULL;
    }

    rc = bpak_crypto_parse_public_key(buffer, (size_t)length, &key);
    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError, "failed to parse public key: %s",
                            bpak_error_string(rc));
    }

    PyObject *result = Py_BuildValue("(iy#)", key->kind, key->data, key->size);

    free(key);

    return result;
}

static PyMethodDef module_methods[] = {
    {"id",
     (PyCFunction)(void (*)(void))m_generate_id,
     METH_VARARGS | METH_KEYWORDS,
     "Convert string to bpak id"
    },

    {"set_log_func",
     (PyCFunction)(void (*)(void))m_set_log_func,
     METH_VARARGS | METH_KEYWORDS,
     "Set logging function callback"
    },

    {"transport_encode",
     (PyCFunction)(void (*)(void))m_transport_encode,
     METH_VARARGS | METH_KEYWORDS,
     "Transport encode from input to output, using origin for diff origin"
    },

    {"transport_decode",
     (PyCFunction)(void (*)(void))m_transport_decode,
     METH_VARARGS | METH_KEYWORDS,
     "Transport decode from input to output, using origin for diff origin"
    },

    {"hash_kind_str",
     (PyCFunction)(void (*)(void))m_hash_kind_str,
     METH_VARARGS | METH_KEYWORDS,
     "Convert hash kind constant to string"
    },

    {"signature_kind_str",
     (PyCFunction)(void (*)(void))m_signature_kind_str,
     METH_VARARGS | METH_KEYWORDS,
     "Convert signature kind constant to string"
    },

    {"id_to_string",
     (PyCFunction)(void (*)(void))m_id_to_string,
     METH_VARARGS | METH_KEYWORDS,
     "Convert bpak id to known string name, or None"
    },

    {"meta_to_string",
     (PyCFunction)(void (*)(void))m_meta_to_string,
     METH_VARARGS | METH_KEYWORDS,
     "Convert metadata to string representation"
    },

    {"add_transport_meta",
     (PyCFunction)(void (*)(void))m_add_transport_meta,
     METH_VARARGS | METH_KEYWORDS,
     "Add transport metadata to a package"
    },

    {"parse_public_key",
     (PyCFunction)(void (*)(void))m_parse_public_key,
     METH_VARARGS | METH_KEYWORDS,
     "Parse a public key from bytes, returns (kind, data)"
    },

    {NULL}
};

static PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "bpak._bpak",
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = module_methods
};


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

    BPAKPackageError = PyErr_NewException("bpak.Error", NULL, NULL);
    Py_XINCREF(BPAKPackageError);
    if (PyModule_AddObject(m_p, "Error", BPAKPackageError) < 0) {
        Py_XDECREF(BPAKPackageError);
        Py_CLEAR(BPAKPackageError);
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

    PyModule_AddIntConstant(m_p, "FLAG_EXCLUDE_FROM_HASH",
                            BPAK_FLAG_EXCLUDE_FROM_HASH);
    PyModule_AddIntConstant(m_p, "FLAG_TRANSPORT", BPAK_FLAG_TRANSPORT);

    return (m_p);
}
