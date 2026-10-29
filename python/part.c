/* Python 3.10 and newer must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>

#include "python_wrapper.h"

PyObject *part_allocate(BPAKPackage *package, bpak_id_t part_id)
{
    BPAKPart *part;

    part = PyObject_New(BPAKPart, &BPAKPartType);

    if (part != NULL) {
        Py_INCREF(package);
        part->package = package;
        part->part_id = part_id;
    }

    return (PyObject *)part;
}

static void part_dealloc(BPAKPart *self)
{
    if (self != NULL) {
        Py_DECREF(self->package);
        PyObject_Del(self);
    }
}

static PyObject *part_repr(PyObject *self)
{
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;
    int rc = 0;

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get partition: %s",
                bpak_error_string(rc));
    }

    return PyUnicode_FromFormat("<bpak.Part '0x%08x' (%d bytes)>", part->part_id,
            bpak_part_size(p));
}

static PyObject *part_get_id(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPart *part = (BPAKPart *)self;

    return PyLong_FromLong(part->part_id);
}

static int part_set_id(PyObject *self, PyObject *value, void *closure)
{
    (void)closure;
    int rc = 0;
    unsigned int part_id;
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;

    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    part_id = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    if (((uint32_t)part_id) != part_id) {
        PyErr_SetString(PyExc_OverflowError, "outside 32-bit range");
        return -1;
    }

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_KeyError, "failed to get partition: %s",
                bpak_error_string(rc));
        return -1;
    }

    p->id = part_id;
    part->part_id = part_id;

    rc = package_write_header(part->package, false);
    if (rc != BPAK_OK) {
        PyErr_SetString(PyExc_IOError, "could not write header");
        return -1;
    }

    return 0;
}

static PyObject *part_get_size(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;
    int rc = 0;

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get partition: %s",
                bpak_error_string(rc));
    }

    return PyLong_FromLong(bpak_part_size(p));
}

static PyObject *part_get_offset(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;
    int rc = 0;

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get partition: %s",
                bpak_error_string(rc));
    }

    return PyLong_FromLong(bpak_part_offset(h, p));
}

/* Fields of the part header, returned by the getters below */
enum part_field {
    PART_INSTALLED_SIZE,
    PART_TRANSPORT_SIZE,
    PART_PAD_BYTES,
    PART_FLAGS,
};

static PyObject *part_get_field(PyObject *self, void *closure)
{
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;
    int rc = 0;

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError,
                            "failed to get partition: %s",
                            bpak_error_string(rc));
    }

    switch ((enum part_field)(intptr_t)closure) {
    case PART_INSTALLED_SIZE:
        return PyLong_FromUnsignedLongLong(p->size);
    case PART_TRANSPORT_SIZE:
        return PyLong_FromUnsignedLongLong(p->transport_size);
    case PART_PAD_BYTES:
        return PyLong_FromLong(p->pad_bytes);
    case PART_FLAGS:
        return PyLong_FromLong(p->flags);
    }

    Py_RETURN_NONE;
}

static PyObject *part_is_transport_encoded(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;
    int rc = 0;

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get partition: %s",
                bpak_error_string(rc));
    }

    if (p->flags & BPAK_FLAG_TRANSPORT) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *part_read_data(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    BPAKPart *part = (BPAKPart *)self;
    struct bpak_header *h = bpak_pkg_header(&part->package->pkg);
    struct bpak_part_header *p;
    PyObject *bytes;
    int rc = 0;

    rc = bpak_get_part(h, part->part_id, &p);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get partition: %s",
                bpak_error_string(rc));
    }

    size_t part_size = bpak_part_size_wo_pad(p);
    size_t read_size;
    FILE *fp = part->package->pkg.fp;

    bytes = PyBytes_FromStringAndSize(NULL, part_size);
    if (!bytes) {
        return NULL;
    }

    if (fseek(fp, bpak_part_offset(h, p), SEEK_SET) < 0) {
        Py_DECREF(bytes);
        return PyErr_Format(PyExc_IOError, "failed to seek: %s",
                strerror(ferror(fp)));
    }

    /* fread returns 0 for empty parts */
    read_size = 1;
    if (part_size > 0) {
        read_size = fread(PyBytes_AsString(bytes), part_size, 1, fp);
    }
    if (read_size != 1) {
        Py_DECREF(bytes);
        return PyErr_Format(PyExc_IOError, "failed to read: %s",
                strerror(ferror(fp)));
    }

    return bytes;
}

static PyObject *part_delete(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = { "remove_meta", NULL };
    BPAKPart *part = (BPAKPart *)self;
    int remove_meta = 1;
    int rc;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "|p:delete",
                                     kwlist,
                                     &remove_meta);
    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_delete_part(&part->package->pkg, part->part_id, remove_meta);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "failed to delete part");
    }

    Py_RETURN_NONE;
}

static PyMethodDef part_methods[] = {
    { "read_data",
      (PyCFunction)(void (*)(void))part_read_data,
      METH_NOARGS,
      "Read all the data into a buffer" },

    { "delete",
      (PyCFunction)(void (*)(void))part_delete,
      METH_VARARGS | METH_KEYWORDS,
      "Delete part and, unless remove_meta is false, its meta data" },

    { NULL }
};

static PyGetSetDef part_getset[] = {
    { "id",
      (getter)part_get_id,
      (setter)part_set_id,
      "Part ID (32-bit)",
      NULL },

    { "size",
      (getter)part_get_size,
      (setter)NULL,
      "Size of the part in the package including padding, or the transport "
      "size if the part is transport encoded",
      NULL },

    { "installed_size",
      (getter)part_get_field,
      (setter)NULL,
      "Size of the part data when it is installed, without padding",
      (void *)PART_INSTALLED_SIZE },

    { "transport_size",
      (getter)part_get_field,
      (setter)NULL,
      "Size of the transport encoded part data",
      (void *)PART_TRANSPORT_SIZE },

    { "pad_bytes",
      (getter)part_get_field,
      (setter)NULL,
      "Number of zero bytes that pad the part to the part alignment",
      (void *)PART_PAD_BYTES },

    { "flags",
      (getter)part_get_field,
      (setter)NULL,
      "Part flags (FLAG_ constants)",
      (void *)PART_FLAGS },

    { "offset",
      (getter)part_get_offset,
      (setter)NULL,
      "Part size offset in the unencoded bytestream, including header",
      NULL },

    { "is_transport_encoded",
      (getter)part_is_transport_encoded,
      (setter)NULL,
      "If part is transport encoded",
      NULL },

    { NULL }
};

PyTypeObject BPAKPartType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "bpak.Part",
    .tp_doc = "BPAK Package part",
    .tp_basicsize = sizeof(BPAKPart),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_dealloc = (destructor)part_dealloc,
    .tp_repr = (reprfunc)part_repr,
    .tp_methods = part_methods,
    .tp_getset = part_getset,
};
