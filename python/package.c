#include <stdio.h>
/* Python 3.10 and newser must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>

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
    BPAKPackage *self;

    self = (BPAKPackage *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

static void package_dealloc(BPAKPackage *self)
{
    bpak_pkg_close(&self->pkg);
    Py_TYPE(self)->tp_free((PyObject *) self);
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

static PyObject *package_size(BPAKPackage *self)
{
    return PyLong_FromLong(bpak_pkg_size(&self->pkg));
}

static PyObject *package_installed_size(BPAKPackage *self)
{
    return PyLong_FromLong(bpak_pkg_installed_size(&self->pkg));
}

static PyObject * package_close(BPAKPackage *self)
{
    bpak_pkg_close(&self->pkg);
    return Py_None;
}

static PyObject * package_hash_kind(BPAKPackage *self)
{
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    return Py_BuildValue("i", h->hash_kind);
}

static PyObject * package_set_hash_kind(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    int hash_kind;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = {"hash_kind", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &hash_kind);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    h->hash_kind = (uint32_t) hash_kind;

    rc = bpak_pkg_write_header(&self->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_sign_kind(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    int sign_kind;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = {"sign_kind", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &sign_kind);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    h->signature_kind = (uint32_t) sign_kind;

    rc = bpak_pkg_write_header(&self->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_signature(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    char *signature_data;
    Py_ssize_t signature_sz;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = {"signature_data", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &signature_data,
                                                               &signature_sz);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    bpak_printf(2, "Sig data: %p, sz = %i\n", signature_data, signature_sz);

    rc = bpak_pkg_sign(&self->pkg, signature_data, signature_sz);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Failed to set signature data");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_key_id(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    long key_id;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = {"key_id", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "l", kwlist, &key_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    bpak_set_key_id(h, (uint32_t) key_id);

    rc = bpak_pkg_write_header(&self->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_set_keystore_id(BPAKPackage *self, PyObject *args,
                                                             PyObject *kwds)
{
    int rc;
    long keystore_id;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = {"keystore_id", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "l", kwlist, &keystore_id);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    bpak_set_keystore_id(h, (uint32_t) keystore_id);

    rc = bpak_pkg_write_header(&self->pkg);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "Could not write header");
        return NULL;
    }

    return Py_None;
}

static PyObject * package_read_raw_meta(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    long meta_id, part_ref_id;
    char *meta_ptr = NULL;
    struct bpak_meta_header *meta_header = NULL;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
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

static PyObject * package_write_raw_meta(BPAKPackage *self, PyObject *args,
                                                        PyObject *kwds)
{
    int rc;
    char *meta_data_in;
    Py_ssize_t meta_data_sz;
    int meta_id, part_ref_id;
    void *meta = NULL;
    struct bpak_meta_header *meta_header = NULL;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = {"meta_id", "part_ref_id", "data", NULL};

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "lly#", kwlist,
                                        &meta_id, &part_ref_id,
                                        &meta_data_in, &meta_data_sz);

    if (!rc) {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    rc = bpak_get_meta_and_header(h, (uint32_t) meta_id,
                                     (uint32_t) part_ref_id,
                                     &meta, NULL, &meta_header);

    if (rc != BPAK_OK || meta == NULL) {
        /* Create new meta data */

        rc = bpak_add_meta(h, (uint32_t) meta_id, (uint32_t) part_ref_id,
                              (void **) &meta, meta_data_sz);

        if (rc != BPAK_OK) {
            PyErr_SetString(BPAKPackageError, "Could not add meta data");
            return NULL;
        }

        memcpy(meta, meta_data_in, meta_data_sz);

        rc = bpak_pkg_write_header(&self->pkg);

        if (rc != BPAK_OK) {
            PyErr_SetString(BPAKPackageError, "Could not write header");
            return NULL;
        }
    } else {
        /* Update and possibly resize existing metadata */

        if (meta_data_sz > meta_header->size) {
            PyErr_SetString(BPAKPackageError, "Growing meta data is currently not supported");
            return NULL;
        }

        memcpy(meta, meta_data_in, meta_data_sz);
        meta_header->size = meta_data_sz;

        rc = bpak_pkg_write_header(&self->pkg);

        if (rc != BPAK_OK) {
            PyErr_SetString(BPAKPackageError, "Could not write header");
            return NULL;
        }
    }

    return Py_None;
}
static PyObject * package_transport_encode(BPAKPackage *self,
                                            PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"origin", "output", NULL};
    int rate_limit_us;
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


    rc = bpak_pkg_transport_encode(&self->pkg, &output->pkg, &origin->pkg);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Transport encoding failed");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject * package_read_digest(BPAKPackage *self)
{
    char digest_data[128];

    size_t hash_size = sizeof(digest_data);

    if (bpak_pkg_compute_header_hash(&self->pkg, digest_data, &hash_size, false) != BPAK_OK)
        return Py_None;

    return Py_BuildValue("y#", digest_data, hash_size);
}

static PyObject * package_read_signature(BPAKPackage *self)
{
    char signature_data[512];

    size_t sig_size = sizeof(signature_data);

    if (bpak_copyz_signature(&self->pkg.header, signature_data, &sig_size) != BPAK_OK)
        return Py_None;

    return Py_BuildValue("y#", signature_data, sig_size);
}

static PyObject * package_deps(BPAKPackage *self)
{
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    int n = 0;

    bpak_foreach_meta(h, m)
    {
        if (m->id == 0x0ba87349) /* bpak-dependency */
            n++;
    }

    if (!n)
    {
        return Py_BuildValue("");
    }

    PyObject *result = PyTuple_New(n);
    n = 0;

    bpak_foreach_meta(h, m)
    {
        if (m->id == 0x0ba87349) /* bpak-dependency */
        {

            char uuid_str[64];
            struct bpak_dependency *d = \
                       (struct bpak_dependency *) &(h->metadata[m->offset]);

            // TODO: Fix this
            //  Use python's uuid functions to parse the uuid byte array instead
            //bpak_uuid_to_string(d->uuid, uuid_str, sizeof(uuid_str));

            PyObject *dep = Py_BuildValue("s s", uuid_str, d->constraint);

            PyTuple_SetItem(result, n++, dep);
        }
    }

    return (PyObject *) result;
}

static PyMethodDef package_methods[] =
{
    {"size", (PyCFunction) package_size, METH_NOARGS,
                "Return the actual size of the archive"},

    {"deps", (PyCFunction) package_deps, METH_NOARGS,
                "Get package dependencies"},

    {"read_digest", (PyCFunction) package_read_digest, METH_NOARGS,
                "Get package digest"},

    {"read_signature", (PyCFunction) package_read_signature, METH_NOARGS,
                "Get package signature"},

    {"close", (PyCFunction) package_close, METH_NOARGS,
                "Close package"},

    {"read_hash_kind", (PyCFunction) package_hash_kind, METH_NOARGS,
                "Get package hash kind"},

    {"set_hash_kind", (PyCFunction) package_set_hash_kind, METH_VARARGS | METH_KEYWORDS,
                "Sets package hash kind"},

    {"set_sign_kind", (PyCFunction) package_set_sign_kind, METH_VARARGS | METH_KEYWORDS,
                "Sets package signature kind"},

    {"set_signature", (PyCFunction) package_set_signature, METH_VARARGS | METH_KEYWORDS,
                "Sets package signature data"},

    {"set_key_id", (PyCFunction) package_set_key_id, METH_VARARGS | METH_KEYWORDS,
                "Sets key id"},

    {"set_keystore_id", (PyCFunction) package_set_keystore_id, METH_VARARGS | METH_KEYWORDS,
                "Sets keystore id"},

    {"transport", (PyCFunction) package_transport_encode, METH_VARARGS | METH_KEYWORDS,
                "Encode package for transport"},

    {"installed_size", (PyCFunction) package_installed_size, METH_NOARGS,
                "Return the installed size of the archive"},

    {"read_raw_meta", (PyCFunction) package_read_raw_meta, METH_VARARGS | METH_KEYWORDS,
                "Read meta data"},

    {"write_raw_meta", (PyCFunction) package_write_raw_meta, METH_VARARGS | METH_KEYWORDS,
                "Write meta data"},
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
    { "id", (PyCFunction)m_id, METH_VARARGS | METH_KEYWORDS,
        "Convert string to bpak id"},
    { "set_log_func", (PyCFunction)m_set_log_func, METH_VARARGS | METH_KEYWORDS,
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

PyMODINIT_FUNC PyInit__bpak(void)
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

    PyModule_AddIntConstant(m_p, "BPAK_DEP_EQ", BPAK_DEP_EQ);
    PyModule_AddIntConstant(m_p, "BPAK_DEP_GT", BPAK_DEP_GT);
    PyModule_AddIntConstant(m_p, "BPAK_DEP_GTE", BPAK_DEP_GTE);

    return (m_p);
}
