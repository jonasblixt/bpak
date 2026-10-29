/* Python 3.10 and newer must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>

#include "module.h"

PyObject *meta_allocate(BPAKPackage *package, bpak_id_t meta_id, bpak_id_t part_ref)
{
    BPAKMeta *meta;

    meta = PyObject_New(BPAKMeta, &BPAKMetaType);

    if (meta != NULL) {
        Py_INCREF(package);
        meta->package = package;
        meta->meta_id = meta_id;
        meta->part_ref = part_ref;
    }

    return (PyObject *)meta;
}

struct bpak_meta_header *package_find_meta(BPAKPackage *package,
                                           bpak_id_t meta_id,
                                           bpak_id_t part_ref)
{
    struct bpak_meta_header *m;
    int rc;

    rc = bpak_get_meta(bpak_pkg_header(&package->pkg), meta_id, part_ref, &m);
    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_KeyError,
                     "failed to get meta: %s",
                     bpak_error_string(rc));
        return NULL;
    }

    return m;
}

/* The header of the meta data, or NULL with KeyError set if it was deleted */
static struct bpak_meta_header *meta_header(BPAKMeta *meta)
{
    return package_find_meta(meta->package, meta->meta_id, meta->part_ref);
}

PyObject *meta_data_bytes(PyObject *value, const char *name)
{
    if (PyUnicode_Check(value)) {
        PyObject *ascii = PyUnicode_AsASCIIString(value);
        if (ascii == NULL) {
            return NULL;
        }

        /* Include the terminating NUL of the bytes object */
        PyObject *result = PyBytes_FromStringAndSize(PyBytes_AS_STRING(ascii),
                                                     PyBytes_GET_SIZE(ascii) + 1);
        Py_DECREF(ascii);
        return result;
    }

    if (PyBytes_Check(value)) {
        Py_INCREF(value);
        return value;
    }

    PyErr_Format(PyExc_TypeError,
                 "%s must be bytes or str, not %.200s",
                 name,
                 Py_TYPE(value)->tp_name);
    return NULL;
}

static void meta_dealloc(BPAKMeta *self)
{
    if (self != NULL) {
        Py_DECREF(self->package);
        PyObject_Del(self);
    }
}

static PyObject *meta_repr(PyObject *self)
{
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_meta_header *m;

    m = meta_header(meta);
    if (m == NULL) {
        return NULL;
    }

    return PyUnicode_FromFormat("<bpak.Meta '0x%08x' (part_id_ref: 0x%08x, size: %d)>",
            meta->meta_id, meta->part_ref, m->size);
}

static PyObject *meta_get_id(PyObject *self, void *closure)
{
    (void)closure;
    BPAKMeta *meta = (BPAKMeta *)self;

    return PyLong_FromUnsignedLong(meta->meta_id);
}

static PyObject *meta_get_part_id_ref(PyObject *self, void *closure)
{
    (void)closure;
    BPAKMeta *meta = (BPAKMeta *)self;

    return PyLong_FromUnsignedLong(meta->part_ref);
}

static PyObject *meta_get_size(PyObject *self, void* closure)
{
    (void)closure;
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_meta_header *m;

    m = meta_header(meta);
    if (m == NULL) {
        return NULL;
    }

    return PyLong_FromLong(m->size);
}

static PyObject *meta_get_rawdata(PyObject *self, void* closure)
{
    (void)closure;
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_header *h = bpak_pkg_header(&meta->package->pkg);
    struct bpak_meta_header *m;

    m = meta_header(meta);
    if (m == NULL) {
        return NULL;
    }

    return PyBytes_FromStringAndSize(bpak_get_meta_ptr(h, m, void), m->size);
}

static int meta_set_rawdata(PyObject *self, PyObject *value, void* closure)
{
    (void)closure;
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_header *h = bpak_pkg_header(&meta->package->pkg);
    struct bpak_meta_header *m;
    int rc = 0;

    if (package_check_open(meta->package) < 0) {
        return -1;
    }

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "cannot delete raw_data");
        return -1;
    }

    m = meta_header(meta);
    if (m == NULL) {
        return -1;
    }

    PyObject *bytes = meta_data_bytes(value, "raw_data");
    if (bytes == NULL) {
        return -1;
    }

    const char *new_data = PyBytes_AS_STRING(bytes);
    Py_ssize_t new_size = PyBytes_GET_SIZE(bytes);

    if (new_size > BPAK_METADATA_BYTES) {
        bpak_raise(-BPAK_SIZE_ERROR,
                   "meta data is %zd bytes, the maximum is %d",
                   new_size,
                   BPAK_METADATA_BYTES);
        rc = -1;
        goto return_out;
    }

    uint8_t *meta_data = bpak_get_meta_ptr(h, m, uint8_t);

    if (new_size > m->size) {
        /* Grow the meta data by removing and adding it again. Work on a copy
         * of the header so that the meta data is kept if there is no space
         * left. */
        struct bpak_header *tmp = PyMem_Malloc(sizeof(*tmp));
        struct bpak_meta_header *tmp_meta;

        if (tmp == NULL) {
            PyErr_NoMemory();
            rc = -1;
            goto return_out;
        }

        memcpy(tmp, h, sizeof(*tmp));

        rc = bpak_get_meta(tmp, meta->meta_id, meta->part_ref, &tmp_meta);
        if (rc == BPAK_OK) {
            bpak_del_meta(tmp, tmp_meta);
            rc = bpak_add_meta(tmp,
                               meta->meta_id,
                               meta->part_ref,
                               new_size,
                               &tmp_meta);
        }

        if (rc != BPAK_OK) {
            PyMem_Free(tmp);
            bpak_raise(rc, "could not grow meta data");
            rc = -1;
            goto return_out;
        }

        memcpy(h, tmp, sizeof(*h));
        PyMem_Free(tmp);

        rc = bpak_get_meta(h, meta->meta_id, meta->part_ref, &m);
        if (rc != BPAK_OK) {
            bpak_raise(rc, "could not grow meta data");
            rc = -1;
            goto return_out;
        }

        meta_data = bpak_get_meta_ptr(h, m, uint8_t);
    }

    memcpy(meta_data, new_data, new_size);
    memset(meta_data + new_size, 0, m->size - new_size);

    rc = package_write_header_or_raise(meta->package, PyExc_OSError);

return_out:
    Py_DECREF(bytes);
    return rc;
}

static PyObject *meta_as_uuid(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    static PyObject *uuid_ctor = NULL;

    if (uuid_ctor == NULL) {
        PyObject *py_uuid = PyImport_ImportModule("uuid");
        if (py_uuid == NULL) {
            return NULL;
        }
        uuid_ctor = PyObject_GetAttrString(py_uuid, "UUID");
        Py_DECREF(py_uuid);
        if (uuid_ctor == NULL) {
            return NULL;
        }
    }

    PyObject *bytes = meta_get_rawdata(self, NULL);

    if (!bytes) {
        return NULL;
    }

    PyObject *result = PyObject_CallFunctionObjArgs(uuid_ctor, Py_None, bytes, NULL);
    Py_DECREF(bytes);
    return result;
}

static PyObject *meta_as_string(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_header *h = bpak_pkg_header(&meta->package->pkg);
    struct bpak_meta_header *m;

    m = meta_header(meta);
    if (m == NULL) {
        return NULL;
    }

    char *meta_ptr = bpak_get_meta_ptr(h, m, char);
    size_t len = strlen(meta_ptr);
    if (len > m->size) {
        len = m->size;
    }

    return PyUnicode_DecodeASCII(meta_ptr, len, "strict");
}

static PyObject *meta_describe(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_header *h = bpak_pkg_header(&meta->package->pkg);
    struct bpak_meta_header *m;
    /* Large enough for any meta data and a terminating NUL */
    char buf[BPAK_METADATA_BYTES + 1] = { 0 };
    int rc = 0;

    m = meta_header(meta);
    if (m == NULL) {
        return NULL;
    }

    rc = bpak_meta_to_string(h, m, buf, sizeof(buf));
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "could not format meta data");
    }

    return PyUnicode_DecodeASCII(buf, strlen(buf), "replace");
}

static PyObject *meta_delete(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    BPAKMeta *meta = (BPAKMeta *)self;
    struct bpak_header *h = bpak_pkg_header(&meta->package->pkg);
    struct bpak_meta_header *m;

    if (package_check_open(meta->package) < 0) {
        return NULL;
    }

    m = meta_header(meta);
    if (m == NULL) {
        return NULL;
    }

    bpak_del_meta(h, m);

    if (package_write_header_or_raise(meta->package, PyExc_OSError) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef meta_methods[] = {
    { "as_uuid",
      (PyCFunction)(void (*)(void))meta_as_uuid,
      METH_NOARGS,
      "Interpret the data as a UUID object" },

    { "as_string",
      (PyCFunction)(void (*)(void))meta_as_string,
      METH_NOARGS,
      "Interpret the data as a string object" },

    { "describe",
      (PyCFunction)(void (*)(void))meta_describe,
      METH_NOARGS,
      "Human readable data of well known meta data, empty for other meta "
      "data" },

    { "delete",
      (PyCFunction)(void (*)(void))meta_delete,
      METH_NOARGS,
      "Delete metadata from package" },

    { NULL }
};

static PyGetSetDef meta_getset[] = {
    {"id",
     (getter)meta_get_id,
     (setter)NULL,
     "Metadata ID (32-bit)",
     NULL},

    {"part_id_ref",
     (getter)meta_get_part_id_ref,
     (setter)NULL,
     "Reference to a part ID (or 0)",
     NULL},

    {"size",
     (getter)meta_get_size,
     (setter)NULL,
     "Size in bytes",
     NULL},

    {"raw_data",
     (getter)meta_get_rawdata,
     (setter)meta_set_rawdata,
     "Raw metadata as bytes",
     NULL},

    {NULL}
};

PyTypeObject BPAKMetaType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "bpak.Meta",
    .tp_doc = "BPAK Package meta",
    .tp_basicsize = sizeof(BPAKMeta),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_dealloc = (destructor)meta_dealloc,
    .tp_repr = (reprfunc)meta_repr,
    .tp_methods = meta_methods,
    .tp_getset = meta_getset,
};
