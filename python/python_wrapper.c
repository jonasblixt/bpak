#include <stdio.h>
/* Python 3.10 and newser must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include <uuid/uuid.h>

typedef struct
{
    PyObject_HEAD
    struct bpak_package pkg;
} BPAKPackage;

static PyObject *BPAKPackageError;
static PyObject *log_func = Py_None;

static PyObject * package_new(PyTypeObject *type, PyObject *args,
                                    PyObject *kwds)
{
    (void) args;
    (void) kwds;
    BPAKPackage *self;

    self = (BPAKPackage *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

static void package_dealloc(BPAKPackage *self)
{
    if (self != NULL) {
        bpak_pkg_close(&self->pkg);
        Py_TYPE(self)->tp_free((PyObject *) self);
        self = NULL;
    }
}

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

static int package_init(BPAKPackage *self, PyObject *args,
                                PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"filename", "mode", NULL};
    char *filename = NULL;
    char *mode = NULL;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "|ss", kwlist,
                                        &filename,
                                        &mode);
    if (!rc) {
        return -1;
    }

    if (!filename || !mode)
    {
        PyErr_SetString(BPAKPackageError, "Could not open package");
        return rc;
    }

    rc = bpak_pkg_open(&self->pkg, filename, mode);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Could not open package");
        return rc;
    }

    return 0;
}

static PyObject *package_size(PyObject* self, PyObject* Py_UNUSED(args))
{
    BPAKPackage *package = (BPAKPackage *) self;
    return PyLong_FromLong(bpak_pkg_size(&package->pkg));
}

static PyObject *package_installed_size(PyObject *self)
{
    BPAKPackage *package = (BPAKPackage *) self;
    return PyLong_FromLong(bpak_pkg_installed_size(&package->pkg));
}

static PyObject * package_close(PyObject* self, PyObject* Py_UNUSED(args))
{
    BPAKPackage *package = (BPAKPackage *) self;
    bpak_pkg_close(&package->pkg);
    return Py_None;
}

static PyObject * package_hash_kind(PyObject* self, PyObject* Py_UNUSED(args))
{
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    return Py_BuildValue("i", h->hash_kind);
}

static PyObject * package_set_hash_kind(PyObject *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    int hash_kind;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    static char *kwlist[] = {"hash_kind", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &hash_kind);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    h->hash_kind = (uint32_t) hash_kind;

    rc = bpak_pkg_write_header(&package->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_sign_kind(PyObject *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    int sign_kind;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    static char *kwlist[] = {"sign_kind", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &sign_kind);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    h->signature_kind = (uint32_t) sign_kind;

    rc = bpak_pkg_write_header(&package->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_signature(PyObject *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    uint8_t *signature_data;
    Py_ssize_t signature_sz;
    static char *kwlist[] = {"signature_data", NULL};
    BPAKPackage *package = (BPAKPackage *) self;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &signature_data,
                                                               &signature_sz);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    rc = bpak_pkg_write_raw_signature(&package->pkg, signature_data, signature_sz);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Failed to set signature data");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_key_id(PyObject *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    long key_id;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    static char *kwlist[] = {"key_id", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "l", kwlist, &key_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    bpak_set_key_id(h, (uint32_t) key_id);

    rc = bpak_pkg_write_header(&package->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_keystore_id(PyObject *self, PyObject *args,
                                                             PyObject *kwds)
{
    int rc;
    long keystore_id;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    static char *kwlist[] = {"keystore_id", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "l", kwlist, &keystore_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    bpak_set_keystore_id(h, (uint32_t) keystore_id);

    rc = bpak_pkg_write_header(&package->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_read_raw_meta(PyObject *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    long meta_id, part_ref_id;
    char *meta_ptr = NULL;
    struct bpak_meta_header *meta_header = NULL;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    static char *kwlist[] = {"meta_id", "part_ref_id", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "ll", kwlist,
                                        &meta_id, &part_ref_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    rc = bpak_get_meta_and_header(h, (uint32_t) meta_id,
                                     (uint32_t) part_ref_id,
                                     (void **) &meta_ptr, NULL,
                                     &meta_header);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Error reading meta data");
        return NULL;
    }

    return Py_BuildValue("y#", meta_ptr, meta_header->size);
}

static PyObject* _write_raw_meta(struct bpak_package *pkg,
                                uint32_t meta_id,
                                uint32_t part_ref_id,
                                uint8_t *buffer,
                                size_t length)
{
    int rc;
    struct bpak_header *h = bpak_pkg_header(pkg);
    void *meta = NULL;
    struct bpak_meta_header *meta_header = NULL;

    rc = bpak_get_meta_and_header(h, meta_id,
                                     part_ref_id,
                                     &meta, NULL, &meta_header);

    if (rc != BPAK_OK || meta == NULL) {
        /* Create new meta data */

        rc = bpak_add_meta(h, (uint32_t) meta_id, (uint32_t) part_ref_id,
                              (void **) &meta, length);

        if (rc != BPAK_OK) {
            PyErr_SetString(BPAKPackageError, "Could not add meta data");
            return NULL;
        }

        memcpy(meta, buffer, length);

        rc = bpak_pkg_write_header(pkg);

        if (rc != BPAK_OK) {
            PyErr_SetString(BPAKPackageError, "Could not write header");
            return NULL;
        }
    } else {
        /* Update and possibly resize existing metadata */

        if (length > meta_header->size) {
            PyErr_SetString(BPAKPackageError, "Growing meta data is currently not supported");
            return NULL;
        }

        memcpy(meta, buffer, length);
        meta_header->size = length;

        rc = bpak_pkg_write_header(pkg);

        if (rc != BPAK_OK) {
            PyErr_SetString(BPAKPackageError, "Could not write header");
            return NULL;
        }
    }

    return Py_None;
}

static PyObject * package_write_raw_meta(PyObject *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    char *meta_data_in;
    Py_ssize_t meta_data_sz;
    int meta_id;
    int part_ref_id = 0;
    BPAKPackage *package = (BPAKPackage *) self;
    static char *kwlist[] = {"meta_id", "part_ref_id", "data", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "lly#", kwlist,
                                        &meta_id, &part_ref_id,
                                        &meta_data_in, &meta_data_sz);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    return _write_raw_meta(&package->pkg, meta_id, part_ref_id,
                            (uint8_t *)meta_data_in, meta_data_sz);
}

static PyObject * package_write_string_meta(PyObject *self, PyObject *args)
{
    int rc;
    char *meta_string;
    int meta_id;
    int part_ref_id = 0;
    BPAKPackage *package = (BPAKPackage *) self;

    rc = PyArg_ParseTuple(args, "ls|l", &meta_id, &meta_string, &part_ref_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    return _write_raw_meta(&package->pkg, meta_id, part_ref_id,
                            (uint8_t *)meta_string, strlen(meta_string) + 1);
}

static PyObject * package_read_string_meta(PyObject *self, PyObject *args)
{
    int rc;
    long meta_id;
    long part_ref_id = 0;
    char *meta_ptr = NULL;
    struct bpak_meta_header *meta_header = NULL;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    rc = PyArg_ParseTuple(args, "l|l", &meta_id, &part_ref_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    rc = bpak_get_meta_and_header(h, (uint32_t) meta_id,
                                     (uint32_t) part_ref_id,
                                     (void **) &meta_ptr, NULL,
                                     &meta_header);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Error reading meta data");
        return NULL;
    }

    return Py_BuildValue("s", meta_ptr);
}

static PyObject * package_read_uuid_meta(PyObject *self, PyObject *args)
{
    int rc;
    long meta_id;
    long part_ref_id = 0;
    char *meta_ptr = NULL;
    char result_uuid[37];
    struct bpak_meta_header *meta_header = NULL;
    BPAKPackage *package = (BPAKPackage *) self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    rc = PyArg_ParseTuple(args, "l|l", &meta_id, &part_ref_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    rc = bpak_get_meta_and_header(h, (uint32_t) meta_id,
                                     (uint32_t) part_ref_id,
                                     (void **) &meta_ptr, NULL,
                                     &meta_header);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Error reading meta data");
        return NULL;
    }
    uuid_t raw_uuid;
    memcpy(raw_uuid, meta_ptr, 16);
    uuid_unparse(raw_uuid, result_uuid);
    return Py_BuildValue("s", result_uuid);
}

static PyObject * package_write_uuid_meta(PyObject *self, PyObject *args)
{
    int rc;
    char *meta_string;
    uint8_t uuid_raw[16];
    int meta_id;
    int part_ref_id = 0;
    BPAKPackage *package = (BPAKPackage *) self;

    rc = PyArg_ParseTuple(args, "ls|l", &meta_id, &meta_string, &part_ref_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    uuid_parse(meta_string, uuid_raw);

    return _write_raw_meta(&package->pkg, meta_id, part_ref_id,
                            uuid_raw, 16);
}

static PyObject * package_verify(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    char *verify_key_path;
    static char *kwlist[] = {"verify_key_path", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
                                     &verify_key_path);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        Py_RETURN_FALSE;
    }

    rc = bpak_pkg_verify(&self->pkg, verify_key_path);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Verification failed");
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyObject * package_sign(PyObject *self, PyObject *args, PyObject *kwds)
{
    int rc;
    char *sign_key_path;
    static char *kwlist[] = {"sign_key_path", NULL};
    BPAKPackage *package = (BPAKPackage *) self;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
                                     &sign_key_path);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        Py_RETURN_FALSE;
    }

    rc = bpak_pkg_sign(&package->pkg, sign_key_path);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Signing failed");
        Py_RETURN_FALSE;
    }

    rc = bpak_pkg_write_header(&package->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not update header");
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyObject * package_transport_encode(PyObject *self,
                                            PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"origin", "output", NULL};
    BPAKPackage *package = (BPAKPackage *) self;
    BPAKPackage *origin;
    BPAKPackage *output;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "|OO", kwlist,
                                        &origin,
                                        &output);
    if (!rc)
    {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }


    rc = bpak_pkg_transport_encode(&package->pkg, &output->pkg, &origin->pkg);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Transport encoding failed");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject * package_transport_decode(PyObject *self,
                                            PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"origin", "output", NULL};
    BPAKPackage *package = (BPAKPackage *) self;
    BPAKPackage *origin;
    BPAKPackage *output;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "|OO", kwlist,
                                        &origin,
                                        &output);
    if (!rc)
    {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }


    rc = bpak_pkg_transport_decode(&package->pkg, &output->pkg, &origin->pkg);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Transport decode failed");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject * package_read_digest(PyObject* self, PyObject* Py_UNUSED(args))
{
    char digest_data[128];
    BPAKPackage *package = (BPAKPackage *) self;

    size_t hash_size = sizeof(digest_data);

    if (bpak_pkg_update_hash(&package->pkg, digest_data, &hash_size) != BPAK_OK)
        return Py_None;

    return Py_BuildValue("y#", digest_data, hash_size);
}

static PyObject * package_read_signature(PyObject* self, PyObject* Py_UNUSED(args))
{
    BPAKPackage *package = (BPAKPackage *) self;
    return Py_BuildValue("y#", package->pkg.header.signature,
                               package->pkg.header.signature_sz);
}

static PyMethodDef package_methods[] =
{
    {"size", package_size, METH_NOARGS, "Return the actual size of the archive"},

    {"read_digest", package_read_digest, METH_NOARGS,
                "Get package digest"},

    {"read_signature", package_read_signature, METH_NOARGS,
                "Get package signature"},

    {"close", package_close, METH_NOARGS,
                "Close package"},

    {"read_hash_kind", package_hash_kind, METH_NOARGS,
                "Get package hash kind"},

    {"set_hash_kind", (PyCFunction)(void(*)(void)) package_set_hash_kind, METH_VARARGS | METH_KEYWORDS,
                "Sets package hash kind"},

    {"set_signature_kind", (PyCFunction)(void(*)(void))package_set_sign_kind, METH_VARARGS | METH_KEYWORDS,
                "Sets package signature kind"},

    {"set_signature", (PyCFunction)(void(*)(void))package_set_signature, METH_VARARGS | METH_KEYWORDS,
                "Sets package signature data"},

    {"set_key_id", (PyCFunction)(void(*)(void))package_set_key_id, METH_VARARGS | METH_KEYWORDS,
                "Sets key id"},

    {"set_keystore_id", (PyCFunction)(void(*)(void))package_set_keystore_id, METH_VARARGS | METH_KEYWORDS,
                "Sets keystore id"},

    {"verify", (PyCFunction)(void(*)(void))package_verify, METH_VARARGS | METH_KEYWORDS,
                "Verify package using a public key"},

    {"sign", (PyCFunction)(void(*)(void))package_sign, METH_VARARGS | METH_KEYWORDS,
                "Sign package using a private key"},

    {"transport_encode", (PyCFunction)(void(*)(void))package_transport_encode, METH_VARARGS | METH_KEYWORDS,
                "Encode package for transport"},

    {"transport_decode", (PyCFunction)(void(*)(void))package_transport_decode, METH_VARARGS | METH_KEYWORDS,
                "Decode transport encoded package"},

    {"installed_size", (PyCFunction)(void(*)(void)) package_installed_size, METH_NOARGS,
                "Return the installed size of the archive"},

    {"read_raw_meta", (PyCFunction)(void(*)(void))package_read_raw_meta, METH_VARARGS | METH_KEYWORDS,
                "Read meta data"},

    {"write_raw_meta", (PyCFunction)(void(*)(void))package_write_raw_meta, METH_VARARGS | METH_KEYWORDS,
                "Write meta data"},

    {"write_string_meta", (PyCFunction)(void(*)(void))package_write_string_meta, METH_VARARGS,
                "Write string meta data"},

    {"read_string_meta", (PyCFunction)(void(*)(void))package_read_string_meta, METH_VARARGS,
                "Read string meta data"},

    {"write_uuid_meta", (PyCFunction)(void(*)(void))package_write_uuid_meta, METH_VARARGS,
                "Write uuid meta data"},

    {"read_uuid_meta", (PyCFunction)(void(*)(void))package_read_uuid_meta, METH_VARARGS,
                "Read uuid meta data"},
    {NULL},
};

static PyTypeObject BPAKPackageType =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "bpak.Package",
    .tp_doc = "BPAK Package",
    .tp_basicsize = sizeof(BPAKPackage),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = package_new,
    .tp_init = (initproc) package_init,
    .tp_dealloc = (destructor) package_dealloc,
    .tp_methods = package_methods,
};

static PyObject * m_id(PyObject *module, PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"string", NULL};
    char *input_string = NULL;
    (void) module;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
                                        &input_string);
    if (!rc)
    {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    return PyLong_FromLong(bpak_id(input_string));
}

static PyObject * m_set_log_func(PyObject *module, PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"log_func", NULL};
    (void) module;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist,
                                        &log_func);
    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    return Py_None;
}


static PyMethodDef module_methods[] =
{
    { "id", (PyCFunction)(void(*)(void))m_id, METH_VARARGS | METH_KEYWORDS,
        "Convert string to bpak id"},
    { "set_log_func", (PyCFunction)(void(*)(void))m_set_log_func, METH_VARARGS | METH_KEYWORDS,
        "Set logging function callback"},
    { NULL }
};

static PyModuleDef module =
{
   PyModuleDef_HEAD_INIT,
   .m_name = "bpak",
   .m_doc = NULL,
   .m_size = -1,
   .m_methods = module_methods
};

PyMODINIT_FUNC PyInit_bpak(void)
{
    PyObject *m_p;

    if (PyType_Ready(&BPAKPackageType) < 0)
        return NULL;

    /* Module creation. */
    m_p = PyModule_Create(&module);

    if (m_p == NULL)
    {
        return (NULL);
    }

    Py_INCREF(&BPAKPackageType);

    if (PyModule_AddObject(m_p, "Package", (PyObject *) &BPAKPackageType) < 0)
    {
        Py_DECREF(&BPAKPackageType);
        Py_DECREF(m_p);
        return NULL;
    }

    BPAKPackageError = PyErr_NewException("bpak.BPAKException", NULL, NULL);
    Py_XINCREF(BPAKPackageError);

    if (PyModule_AddObject(m_p, "BPAKException", BPAKPackageError) < 0)
    {
        Py_XDECREF(BPAKPackageError);
        Py_CLEAR(BPAKPackageError);
        Py_DECREF(&BPAKPackageType);
        Py_DECREF(m_p);
        return NULL;
    }

    PyModule_AddIntConstant(m_p, "BPAK_HASH_SHA256", BPAK_HASH_SHA256);
    PyModule_AddIntConstant(m_p, "BPAK_HASH_SHA384", BPAK_HASH_SHA384);
    PyModule_AddIntConstant(m_p, "BPAK_HASH_SHA512", BPAK_HASH_SHA512);

    PyModule_AddIntConstant(m_p, "BPAK_SIGN_RSA4096", BPAK_SIGN_RSA4096);
    PyModule_AddIntConstant(m_p, "BPAK_SIGN_PRIME256v1", BPAK_SIGN_PRIME256v1);
    PyModule_AddIntConstant(m_p, "BPAK_SIGN_SECP384r1", BPAK_SIGN_SECP384r1);
    PyModule_AddIntConstant(m_p, "BPAK_SIGN_SECP521r1", BPAK_SIGN_SECP521r1);
    return (m_p);
}
