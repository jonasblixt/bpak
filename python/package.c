/* Python 3.10 and newer must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/id.h>
#include <bpak/crypto.h>

#include "python_wrapper.h"

int package_write_header(BPAKPackage *package, bool update_hash)
{
    int rc = 0;

    if (update_hash) {
        rc = bpak_pkg_update_hash(&package->pkg, NULL, NULL);
        if (rc < 0) {
            return rc;
        }
    }

    rc = bpak_pkg_write_header(&package->pkg);
    fflush(package->pkg.fp);

    return rc;
}

static PyObject *package_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    (void)args;
    (void)kwds;
    BPAKPackage *self;

    self = (BPAKPackage *)type->tp_alloc(type, 0);
    if (self != NULL) {
        memset(&self->pkg, 0, sizeof(struct bpak_package));
    }
    return (PyObject *)self;
}

static void package_dealloc(BPAKPackage *self)
{
    if (self != NULL) {
        bpak_pkg_close(&self->pkg);
        Py_TYPE(self)->tp_free((PyObject *)self);
    }
}

static int package_init(BPAKPackage *self, PyObject *args, PyObject *kwds)
{
    int rc;
    static char *kwlist[] = {"filename", "mode", NULL};
    PyObject *filename;
    char *mode = NULL;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "O&s:bpak.Package.__init__",
                                     kwlist,
                                     &PyUnicode_FSDecoder,
                                     &filename,
                                     &mode);
    if (!rc) {
        return -1;
    }

    PyObject *filename_ascii = PyUnicode_AsASCIIString(filename);
    if (!filename_ascii) {
        return -1;
    }

    rc = bpak_pkg_open(&self->pkg, PyBytes_AsString(filename_ascii), mode);

    Py_DECREF(filename_ascii);

    if (rc != BPAK_OK) {
        PyErr_SetString(BPAKPackageError, "could not open package");
        return rc;
    }

    return 0;
}

static PyObject *package_close(PyObject *self, PyObject *Py_UNUSED(args))
{
    BPAKPackage *package = (BPAKPackage *)self;

    bpak_pkg_close(&package->pkg);
    memset(&package->pkg, 0, sizeof(package->pkg));

    Py_RETURN_NONE;
}

static PyObject *package_verify(BPAKPackage *self, PyObject *args,
                                PyObject *kwds)
{
    int rc;
    PyObject *verify_key_filename;
    struct bpak_key *key = NULL;
    static char *kwlist[] = {"verify_key_path", NULL};

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "O&:verify",
                                     kwlist,
                                     &PyUnicode_FSDecoder,
                                     &verify_key_filename);

    if (!rc) {
        return NULL;
    }

    PyObject *filename_ascii = PyUnicode_AsASCIIString(verify_key_filename);
    if (!filename_ascii) {
        return NULL;
    }

    rc = bpak_crypto_load_public_key(PyBytes_AsString(filename_ascii), &key);

    Py_DECREF(filename_ascii);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError, "could not load key: %s",
                bpak_error_string(rc));
    }

    rc = bpak_pkg_verify(&self->pkg, key);

    free(key);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError, "verification failed");
    }

    Py_RETURN_TRUE;
}

static PyObject *package_sign(PyObject *self, PyObject *args, PyObject *kwds)
{
    int rc;
    PyObject *sign_key_filename;
    static char *kwlist[] = {"sign_key_path", NULL};
    BPAKPackage *package = (BPAKPackage *)self;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "O&:verify",
                                     kwlist,
                                     &PyUnicode_FSDecoder,
                                     &sign_key_filename);

    if (!rc) {
        return NULL;
    }

    PyObject *filename_ascii = PyUnicode_AsASCIIString(sign_key_filename);
    if (!filename_ascii) {
        return NULL;
    }

    rc = bpak_pkg_sign(&package->pkg, PyBytes_AsString(filename_ascii));

    Py_DECREF(filename_ascii);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError, "signing failed: %s",
                bpak_error_string(rc));
    }

    Py_RETURN_TRUE;
}

static PyObject *package_add_file(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"part_name", "filename", "with_merkle_tree", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    struct bpak_part_header *part;
    int rc;
    const char *part_name = NULL;
    PyObject *filename;
    int with_merkle_tree = 0;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "sO&|p:add_file",
                                     kwlist,
                                     &part_name,
                                     &PyUnicode_FSDecoder,
                                     &filename,
                                     &with_merkle_tree);

    if (!rc) {
        return NULL;
    }

    PyObject *filename_ascii = PyUnicode_AsASCIIString(filename);
    if (!filename_ascii) {
        return NULL;
    }

    if (with_merkle_tree) {
        rc = bpak_pkg_add_file_with_merkle_tree(&package->pkg,
                PyBytes_AsString(filename_ascii), part_name, 0);
    } else {
        rc = bpak_pkg_add_file(&package->pkg, PyBytes_AsString(filename_ascii),
                part_name, 0);
    }

    Py_DECREF(filename_ascii);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError, "Failed to add file to package: %s",
                bpak_error_string(rc));
    }

    rc = bpak_get_part(h, bpak_id(part_name), &part);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get part: %s",
                bpak_error_string(rc));
    }

    return part_allocate(package, part->id);
}

static PyObject *package_add_key(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"part_name", "filename", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    struct bpak_part_header *part;
    int rc;
    const char *part_name = NULL;
    PyObject *filename;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "sO&:add_key",
                                     kwlist,
                                     &part_name,
                                     &PyUnicode_FSDecoder,
                                     &filename);

    if (!rc) {
        return NULL;
    }

    PyObject *filename_ascii = PyUnicode_AsASCIIString(filename);
    if (!filename_ascii) {
        return NULL;
    }


    rc = bpak_pkg_add_key(&package->pkg, PyBytes_AsString(filename_ascii), part_name, 0);

    Py_DECREF(filename_ascii);

    if (rc != BPAK_OK) {
        return PyErr_Format(BPAKPackageError, "failed to add key to package: %s",
                bpak_error_string(rc));
    }

    rc = bpak_get_part(h, bpak_id(part_name), &part);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get part: %s",
                bpak_error_string(rc));
    }

    return part_allocate(package, part->id);
}

static PyObject *package_add_meta(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"id", "part_id_ref", "data", "size", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    struct bpak_meta_header *meta;
    int rc;
    bpak_id_t meta_id;
    bpak_id_t part_ref = 0;
    PyObject *data = NULL;
    Py_ssize_t size = -1;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "I|IOn:add_meta",
                                     kwlist,
                                     &meta_id,
                                     &part_ref,
                                     &data,
                                     &size);

    if (!rc) {
        return NULL;
    }

    if (!data && size < 0) {
        return PyErr_Format(PyExc_TypeError, "must specify either initial data or size");
    }

    Py_ssize_t new_size = 0;
    char *new_data = NULL;
    bool was_unicode = false;

    if (data) {
        if (PyUnicode_Check(data)) {
            PyObject *bytes = PyUnicode_AsASCIIString(data);
            if (!bytes) {
                return NULL;
            }
            data = bytes;
            was_unicode = true;
        }

        if (PyBytes_Check(data)) {
            if (PyBytes_AsStringAndSize(data, &new_data, &new_size) < 0) {
                return NULL;
            }
        } else {
            PyErr_SetString(PyExc_TypeError, "type mismatch, data must be bytes or str");
            return NULL;
        }

        if (was_unicode) {
            new_size++;
        }

        if (size < 0) {
            size = new_size;
        }
    }

    rc = bpak_add_meta(h, meta_id, part_ref, size, &meta);
    if (rc != BPAK_OK) {
        PyErr_Format(BPAKPackageError, "failed to add metadata: %s",
                bpak_error_string(rc));
        goto err_out;
    }

    size_t to_copy = new_size;
    if ((ssize_t)to_copy > size) {
        to_copy = size;
    }

    uint8_t *meta_ptr = bpak_get_meta_ptr(h, meta, uint8_t);

    if (to_copy > 0) {
        memcpy(meta_ptr, new_data, to_copy);
    }

    if (was_unicode) {
        Py_DECREF(data);
    }

    rc = package_write_header(package, false);
    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_IOError, "could not write header: %s",
                bpak_error_string(rc));
        goto err_out;
    }

    return meta_allocate(package, meta->id, meta->part_id_ref);

err_out:
    if (was_unicode) {
        Py_DECREF(data);
    }

    return NULL;
}

static PyObject *package_get_part(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"id", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    struct bpak_part_header *part;
    int rc;
    bpak_id_t part_id;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "I:get_part",
                                     kwlist,
                                     &part_id);

    if (!rc) {
        return NULL;
    }

    rc = bpak_get_part(h, part_id, &part);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get part: %s",
                bpak_error_string(rc));
    }

    return part_allocate(package, part->id);
}

static PyObject *package_get_meta(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"id", "part_id_ref", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    struct bpak_meta_header *meta;
    int rc;
    bpak_id_t meta_id;
    bpak_id_t part_ref = 0;

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "I|I:get_meta",
                                     kwlist,
                                     &meta_id,
                                     &part_ref);

    if (!rc) {
        return NULL;
    }

    rc = bpak_get_meta(h, meta_id, part_ref, &meta);
    if (rc != BPAK_OK) {
        return PyErr_Format(PyExc_KeyError, "failed to get meta: %s",
                bpak_error_string(rc));
    }

    return meta_allocate(package, meta->id, meta->part_id_ref);
}

static PyObject *package_enter(PyObject *self, PyObject *Py_UNUSED(args))
{
    Py_INCREF(self);

    return self;
}

static PyObject *package_exit(PyObject *self, PyObject *args)
{
    package_close(self, args);

    Py_RETURN_NONE;
}

/* Getters and setters */

static PyObject *package_get_digest(PyObject *self, void *closure)
{
    (void)closure;
    char digest_data[128];
    BPAKPackage *package = (BPAKPackage *)self;

    size_t hash_size = sizeof(digest_data);

    if (bpak_pkg_update_hash(&package->pkg, digest_data, &hash_size) != BPAK_OK)
        Py_RETURN_NONE;

    return Py_BuildValue("y#", digest_data, hash_size);
}

static PyObject *package_get_hash_kind(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    return PyLong_FromLong(h->hash_kind);
}

static int package_set_hash_kind(PyObject *self, PyObject *value, void *closure)
{
    (void)closure;
    int rc;
    int hash_kind;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    hash_kind = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }

    h->hash_kind = (uint32_t)hash_kind;

    rc = package_write_header(package, false);

    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_IOError, "could not write header: %s",
                bpak_error_string(rc));
        return -1;
    }

    return 0;
}

static PyObject *package_get_key_id(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    return PyLong_FromLong(h->key_id);
}

static int package_set_key_id(PyObject *self, PyObject *value, void *closure)
{
    (void)closure;
    int rc;
    int key_id;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    key_id = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }

    h->key_id = (uint32_t)key_id;

    rc = package_write_header(package, false);

    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_IOError, "could not write header: %s",
                bpak_error_string(rc));
        return -1;
    }

    return 0;
}

static PyObject *package_get_keystore_id(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    return PyLong_FromLong(h->keystore_id);
}

static int package_set_keystore_id(PyObject *self, PyObject *value, void *closure)
{
    (void)closure;
    int rc;
    int keystore_id;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    keystore_id = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }

    h->keystore_id = (uint32_t)keystore_id;

    rc = package_write_header(package, false);

    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_IOError, "could not write header: %s",
                bpak_error_string(rc));
        return -1;
    }

    return 0;
}

static PyObject *package_get_signature(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;

    return Py_BuildValue("y#",
                         package->pkg.header.signature,
                         package->pkg.header.signature_sz);
}

static int package_set_signature(PyObject *self, PyObject *value,
                                 void *closure)
{
    (void)closure;

    int rc;
    static const uint8_t empty_signature[1] = {0};
    uint8_t *signature_data;
    Py_ssize_t signature_sz;
    BPAKPackage *package = (BPAKPackage *)self;

    /* Handle clearing / del */
    if (value == NULL || value == Py_None) {
        bpak_pkg_write_raw_signature(&package->pkg, empty_signature, 0);
        return 0;
    }

    if (!PyBytes_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    if (PyBytes_AsStringAndSize(value, (char**)&signature_data, &signature_sz) < 0) {
        return -1;
    }

    rc = bpak_pkg_write_raw_signature(&package->pkg,
                                      signature_data,
                                      signature_sz);

    if (rc != BPAK_OK) {
        PyErr_Format(BPAKPackageError, "failed to set signature data: %s",
                bpak_error_string(rc));
        return -1;
    }

    return 0;
}

static PyObject *package_get_signature_kind(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    return PyLong_FromLong(h->signature_kind);
}

static int package_set_signature_kind(PyObject *self, PyObject *value, void *closure)
{
    (void)closure;
    int rc;
    int signature_kind;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);

    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    signature_kind = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }

    h->signature_kind = (uint32_t)signature_kind;

    rc = package_write_header(package, false);

    if (rc != BPAK_OK) {
        PyErr_Format(PyExc_IOError, "could not write header: %s",
                bpak_error_string(rc));
        return -1;
    }

    return 0;
}

static PyObject *package_get_size(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    return PyLong_FromLong(bpak_pkg_size(&package->pkg));
}

static PyObject *package_get_installed_size(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    return PyLong_FromLong(bpak_pkg_installed_size(&package->pkg));
}

static PyObject *package_get_parts(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *hdr = bpak_pkg_header(&package->pkg);

    PyObject *list = NULL;
    PyObject *part = NULL;
    int rc;

    list = PyList_New(0);
    if (!list) {
        return NULL;
    }

    unsigned int idx = 0;
    bpak_foreach_part(hdr, p) {
        if (!p->id) {
            break;
        }

        part = part_allocate(package, p->id);
        if (!part) {
            Py_DECREF(list);

            return PyErr_NoMemory();
        }

        rc = PyList_Append(list, part);
        if (rc < 0) {
            Py_DECREF(list);

            return NULL;
        }

        idx++;
    }

    return list;
}

static PyObject *package_get_meta_list(PyObject *self, void *closure)
{
    (void)closure;
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *hdr = bpak_pkg_header(&package->pkg);

    PyObject *list = NULL;
    PyObject *meta = NULL;
    int rc;

    list = PyList_New(0);
    if (!list) {
        return NULL;
    }

    unsigned int idx = 0;
    bpak_foreach_meta(hdr, m) {
        if (!m->id) {
            break;
        }

        meta = meta_allocate(package, m->id, m->part_id_ref);
        if (!meta) {
            Py_DECREF(list);

            return PyErr_NoMemory();
        }

        rc = PyList_Append(list, meta);
        if (rc < 0) {
            Py_DECREF(list);

            return NULL;
        }

        idx++;
    }

    return list;
}

static PyMethodDef package_methods[] = {
    {"close",
     (PyCFunction)(void (*)(void))package_close,
     METH_NOARGS,
     "Close package"},

    {"verify",
     (PyCFunction)(void (*)(void))package_verify,
     METH_VARARGS | METH_KEYWORDS,
     "Verify package using a public key"},

    {"sign",
     (PyCFunction)(void (*)(void))package_sign,
     METH_VARARGS | METH_KEYWORDS,
     "Sign package using a private key"},

    {"add_file",
     (PyCFunction)(void (*)(void))package_add_file,
     METH_VARARGS | METH_KEYWORDS,
     "Create a new part object from a file"},

    {"add_key",
     (PyCFunction)(void (*)(void))package_add_key,
     METH_VARARGS | METH_KEYWORDS,
     "Create a new part object from a key file"},

    {"add_meta",
     (PyCFunction)(void (*)(void))package_add_meta,
     METH_VARARGS | METH_KEYWORDS,
     "Create a new metadata object"},

    {"get_part",
     (PyCFunction)(void (*)(void))package_get_part,
     METH_VARARGS | METH_KEYWORDS,
     "Get a reference to a specific part object"},

    {"get_meta",
     (PyCFunction)(void (*)(void))package_get_meta,
     METH_VARARGS | METH_KEYWORDS,
     "Get a reference to a specific metadata object"},

    /* For context manager use */
    {"__enter__",
     (PyCFunction)(void (*)(void))package_enter,
     METH_VARARGS,
     ""},
    {"__exit__",
     (PyCFunction)(void (*)(void))package_exit,
     METH_VARARGS,
     ""},

    {NULL},
};

static PyGetSetDef package_getset[] = {
    {"digest",
     (getter)package_get_digest,
     (setter)NULL,
     "Package digest (header hash)",
     NULL},

    {"hash_kind",
     (getter)package_get_hash_kind,
     (setter)package_set_hash_kind,
     "Package hash kind (one of HASH_ constants)",
     NULL},

    {"installed_size",
     (getter)package_get_installed_size,
     (setter)NULL,
     "The installed size of package",
     NULL},

    {"key_id",
     (getter)package_get_key_id,
     (setter)package_set_key_id,
     "Key ID used for signing/verification",
     NULL},

    {"keystore_id",
     (getter)package_get_keystore_id,
     (setter)package_set_keystore_id,
     "Keystore ID used for signing",
     NULL},

    {"signature",
     (getter)package_get_signature,
     (setter)package_set_signature,
     "Package signature (possibly empty if unsigned)",
     NULL},

    {"signature_kind",
     (getter)package_get_signature_kind,
     (setter)package_set_signature_kind,
     "Package signature kind (one of SIGN_ constants)",
     NULL},

    {"size",
     (getter)package_get_size,
     (setter)NULL,
     "The actual size of the archive",
     NULL},

    {"parts",
     (getter)package_get_parts,
     (setter)NULL,
     "List of all parts in package",
     NULL},

    {"meta",
     (getter)package_get_meta_list,
     (setter)NULL,
     "List of all parts in package",
     NULL},


    {NULL},
};

PyTypeObject BPAKPackageType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "bpak.Package",
    .tp_doc = "BPAK Package",
    .tp_basicsize = sizeof(BPAKPackage),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = package_new,
    .tp_init = (initproc)package_init,
    .tp_dealloc = (destructor)package_dealloc,
    .tp_methods = package_methods,
    .tp_getset = package_getset,
};
