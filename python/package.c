#include <stdio.h>
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>

typedef struct
{
    PyObject_HEAD
    struct bpak_package *pkg;
} BPAKPackage;

static PyObject *BPAKPackageError;
static PyObject *log_func = Py_None;

static PyObject * package_new(PyTypeObject *type, PyObject *args,
                                    PyObject *kwds)
{
    BPAKPackage *self;

    self = (BPAKPackage *) type->tp_alloc(type, 0);

    if (self != NULL)
    {
        self->pkg = NULL;
    }

    return (PyObject *) self;
}

static void package_dealloc(BPAKPackage *self)
{
    if (self->pkg)
        bpak_pkg_close(self->pkg);
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
        PyEval_CallFunction(log_func, "(is)", verbosity, log_buf);
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
    return PyLong_FromLong(bpak_pkg_size(self->pkg));
}

static PyObject *package_installed_size(BPAKPackage *self)
{
    return PyLong_FromLong(bpak_pkg_installed_size(self->pkg));
}

static PyObject * package_id(BPAKPackage *self)
{
    struct bpak_header *h = bpak_pkg_header(self->pkg);
    uint8_t *id_p = NULL;
    int rc;
    char uuid_str[64];

                        /* bpak-package */
    rc = bpak_get_meta(h, 0xfb2f1f3f, (void **) &id_p);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Could not read id");
        return NULL;
    }

    bpak_uuid_to_string(id_p, uuid_str, sizeof(uuid_str));

    return Py_BuildValue("s", uuid_str);
}

static PyObject * package_version(BPAKPackage *self)
{
    struct bpak_header *h = bpak_pkg_header(self->pkg);
    char *version = NULL;
    int rc = 0;

                          /* bpak-version */
    rc = bpak_get_meta(h, 0x9a5bab69, (void **) &version);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Could not read verison");
        return NULL;
    }

    return Py_BuildValue("s", version);
}

static PyObject * package_transport_encode(BPAKPackage *self,
                                            PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"origin", "output", "rate_limit_us", NULL};
    int rate_limit_us;
    BPAKPackage *origin;
    BPAKPackage *output;

    rc = PyArg_ParseTupleAndKeywords(args, kwds, "|OOi", kwlist,
                                        &origin,
                                        &output,
                                        &rate_limit_us);
    if (!rc)
    {
        PyErr_SetString(BPAKPackageError, "Invalid argument");
        return NULL;
    }

    printf("origin = %p, rate_limit_us = %i us\n", origin, rate_limit_us);

    rc = bpak_pkg_transport_encode(self->pkg, output->pkg, origin->pkg,
                                   rate_limit_us);

    if (rc != BPAK_OK)
    {
        PyErr_SetString(BPAKPackageError, "Transport encoding failed");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject * package_deps(BPAKPackage *self)
{
    struct bpak_header *h = bpak_pkg_header(self->pkg);
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
        if (m->id == 0x0ba87349) /* bpak-transport */
        {

            char uuid_str[64];
            struct bpak_dependency *d = \
                       (struct bpak_dependency *) &(h->metadata[m->offset]);

            bpak_uuid_to_string(d->uuid, uuid_str, sizeof(uuid_str));

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

    {"version", (PyCFunction) package_version, METH_NOARGS,
                "Get package version"},

    {"id", (PyCFunction) package_id, METH_NOARGS,
                "Get package id"},

    {"transport", (PyCFunction) package_transport_encode, METH_VARARGS | METH_KEYWORDS,
                "Encode package for transport"},

    {"installed_size", (PyCFunction) package_installed_size, METH_NOARGS,
                "Return the installed size of the archive"},
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

    if (bpak_pkg_register_all_algs() != BPAK_OK)
        return NULL;

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
