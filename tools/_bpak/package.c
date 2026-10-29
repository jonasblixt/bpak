/* Python 3.10 and newer must set PY_SSIZE_T_CLEAN when using # variant
 *  when parsing arguments */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/id.h>
#include <bpak/crypto.h>
#include <bpak/keystore.h>

#include "module.h"

int package_write_header_or_raise(BPAKPackage *package, PyObject *exc)
{
    int rc;

    rc = bpak_pkg_write_header(&package->pkg);
    fflush(package->pkg.fp);

    if (rc == BPAK_OK) {
        return 0;
    }

    if (exc == NULL) {
        bpak_raise(rc, "could not write header");
    } else {
        PyErr_Format(exc, "could not write header: %s", bpak_error_string(rc));
    }

    return -1;
}

int package_check_open(BPAKPackage *package)
{
    /* close() and a failed open clear the package */
    if (package->pkg.fp == NULL) {
        PyErr_SetString(PyExc_ValueError, "I/O operation on closed package");
        return -1;
    }

    return 0;
}

static PyObject *package_new(PyTypeObject *type, PyObject *Py_UNUSED(args),
                             PyObject *Py_UNUSED(kwds))
{
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
                                     &PyUnicode_FSConverter,
                                     &filename,
                                     &mode);
    if (!rc) {
        return -1;
    }

    rc = bpak_pkg_open(&self->pkg, PyBytes_AsString(filename), mode);

    Py_DECREF(filename);

    if (rc != BPAK_OK) {
        /* bpak_pkg_open closes the file on errors but leaves 'fp' set, the
         * dealloc would close it again */
        memset(&self->pkg, 0, sizeof(self->pkg));
        bpak_raise(rc, "could not open package");
        return -1;
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
    PyObject *verify_key_filename = NULL;
    PyObject *keystore_filename = NULL;
    PyObject *filename_bytes;
    struct bpak_key *key = NULL;
    struct bpak_header *h = bpak_pkg_header(&self->pkg);
    static char *kwlist[] = { "verify_key_path", "keystore_path", NULL };

    if (package_check_open(self) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "|O&$O&:verify",
                                     kwlist,
                                     &PyUnicode_FSConverter,
                                     &verify_key_filename,
                                     &PyUnicode_FSConverter,
                                     &keystore_filename);

    if (!rc) {
        return NULL;
    }

    if ((verify_key_filename == NULL) == (keystore_filename == NULL)) {
        Py_XDECREF(verify_key_filename);
        Py_XDECREF(keystore_filename);
        PyErr_SetString(PyExc_TypeError,
                        "either verify_key_path or keystore_path is required");
        return NULL;
    }

    filename_bytes =
        verify_key_filename ? verify_key_filename : keystore_filename;

    if (verify_key_filename != NULL) {
        rc =
            bpak_crypto_load_public_key(PyBytes_AsString(filename_bytes), &key);
    } else {
        /* The keystore selects the key with the key-id and keystore-id of
         * the package */
        rc = bpak_keystore_load_key_from_file(PyBytes_AsString(filename_bytes),
                                              h->keystore_id,
                                              h->key_id,
                                              NULL,
                                              NULL,
                                              &key);
    }

    Py_DECREF(filename_bytes);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "could not load key");
    }

    rc = bpak_pkg_verify(&self->pkg, key);

    bpak_free(key);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "verification failed");
    }

    Py_RETURN_TRUE;
}

static PyObject *package_sign(PyObject *self, PyObject *args, PyObject *kwds)
{
    int rc;
    PyObject *sign_key_filename;
    static char *kwlist[] = {"sign_key_path", NULL};
    BPAKPackage *package = (BPAKPackage *)self;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "O&:sign",
                                     kwlist,
                                     &PyUnicode_FSConverter,
                                     &sign_key_filename);

    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_sign(&package->pkg, PyBytes_AsString(sign_key_filename));

    Py_DECREF(sign_key_filename);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "signing failed");
    }

    Py_RETURN_TRUE;
}

static PyObject *package_add_file(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = { "part_name",
                              "filename",
                              "with_merkle_tree",
                              "flags",
                              NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    const char *part_name = NULL;
    PyObject *filename;
    int with_merkle_tree = 0;
    unsigned char flags = 0;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "sO&|pb:add_file",
                                     kwlist,
                                     &part_name,
                                     &PyUnicode_FSConverter,
                                     &filename,
                                     &with_merkle_tree,
                                     &flags);

    if (!rc) {
        return NULL;
    }

    if (with_merkle_tree) {
        rc = bpak_pkg_add_file_with_merkle_tree(&package->pkg,
                                                PyBytes_AsString(filename),
                                                part_name,
                                                flags);
    } else {
        rc = bpak_pkg_add_file(&package->pkg,
                               PyBytes_AsString(filename),
                               part_name,
                               flags);
    }

    Py_DECREF(filename);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "Failed to add file to package");
    }

    return part_allocate(package, bpak_id(part_name));
}

static PyObject *package_add_key(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = { "part_name", "filename", "flags", NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    const char *part_name = NULL;
    PyObject *filename;
    unsigned char flags = 0;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "sO&|b:add_key",
                                     kwlist,
                                     &part_name,
                                     &PyUnicode_FSConverter,
                                     &filename,
                                     &flags);

    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_add_key(&package->pkg,
                          PyBytes_AsString(filename),
                          part_name,
                          flags);

    Py_DECREF(filename);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "failed to add key to package");
    }

    return part_allocate(package, bpak_id(part_name));
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

    if (package_check_open(package) < 0) {
        return NULL;
    }

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

    PyObject *bytes = NULL;
    Py_ssize_t new_size = 0;

    if (data) {
        bytes = meta_data_bytes(data, "data");
        if (bytes == NULL) {
            return NULL;
        }

        new_size = PyBytes_GET_SIZE(bytes);
        if (size < 0) {
            size = new_size;
        }
    }

    /* bpak_add_meta takes the size as uint16_t */
    if (size > BPAK_METADATA_BYTES) {
        bpak_raise(-BPAK_SIZE_ERROR,
                   "meta data is %zd bytes, the maximum is %d",
                   size,
                   BPAK_METADATA_BYTES);
        goto err_out;
    }

    rc = bpak_add_meta(h, meta_id, part_ref, size, &meta);
    if (rc != BPAK_OK) {
        bpak_raise(rc, "failed to add metadata");
        goto err_out;
    }

    size_t to_copy = new_size;
    if ((ssize_t)to_copy > size) {
        to_copy = size;
    }

    uint8_t *meta_ptr = bpak_get_meta_ptr(h, meta, uint8_t);

    if (to_copy > 0) {
        memcpy(meta_ptr, PyBytes_AS_STRING(bytes), to_copy);
    }

    Py_CLEAR(bytes);

    if (package_write_header_or_raise(package, PyExc_OSError) < 0) {
        return NULL;
    }

    return meta_allocate(package, meta_id, part_ref);

err_out:
    Py_XDECREF(bytes);
    return NULL;
}

static PyObject *package_get_part(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"id", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
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

    if (package_find_part(package, part_id) == NULL) {
        return NULL;
    }

    return part_allocate(package, part_id);
}

static PyObject *package_get_meta(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"id", "part_id_ref", NULL};
    BPAKPackage *package = (BPAKPackage *)self;
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

    if (package_find_meta(package, meta_id, part_ref) == NULL) {
        return NULL;
    }

    return meta_allocate(package, meta_id, part_ref);
}

/* Compute the payload hash and return the header hash */
static PyObject *package_update_hash(PyObject *self, PyObject *Py_UNUSED(args))
{
    int rc;
    char digest_data[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(digest_data);
    BPAKPackage *package = (BPAKPackage *)self;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = bpak_pkg_update_hash(&package->pkg, digest_data, &hash_size);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "could not compute hash");
    }

    return Py_BuildValue("y#", digest_data, (Py_ssize_t)hash_size);
}

static PyObject *package_write_header_method(PyObject *self,
                                             PyObject *Py_UNUSED(args))
{
    if (package_check_open((BPAKPackage *)self) < 0) {
        return NULL;
    }

    if (package_write_header_or_raise((BPAKPackage *)self, NULL) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *package_add_transport_meta(PyObject *self, PyObject *args,
                                            PyObject *kwds)
{
    static char *kwlist[] = { "part_id", "encoder_id", "decoder_id", NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    bpak_id_t part_id;
    bpak_id_t encoder_id;
    bpak_id_t decoder_id;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "III:add_transport_meta",
                                     kwlist,
                                     &part_id,
                                     &encoder_id,
                                     &decoder_id);
    if (!rc) {
        return NULL;
    }

    rc = bpak_add_transport_meta(bpak_pkg_header(&package->pkg),
                                 part_id,
                                 encoder_id,
                                 decoder_id);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "could not add transport meta data");
    }

    if (package_write_header_or_raise(package, NULL) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *package_delete_part(PyObject *self, PyObject *args,
                                     PyObject *kwds)
{
    static char *kwlist[] = { "id", "remove_meta", NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    bpak_id_t part_id;
    int remove_meta = 1;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "I|p:delete_part",
                                     kwlist,
                                     &part_id,
                                     &remove_meta);
    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_delete_part(&package->pkg, part_id, remove_meta);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "failed to delete part");
    }

    Py_RETURN_NONE;
}

static PyObject *package_delete_all_parts(PyObject *self, PyObject *args,
                                          PyObject *kwds)
{
    static char *kwlist[] = { "remove_meta", NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    int remove_meta = 1;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "|p:delete_all_parts",
                                     kwlist,
                                     &remove_meta);
    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_delete_all_parts(&package->pkg, remove_meta);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "failed to delete parts");
    }

    Py_RETURN_NONE;
}

static PyObject *package_part_sha256(PyObject *self, PyObject *args,
                                     PyObject *kwds)
{
    static char *kwlist[] = { "id", NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    bpak_id_t part_id;
    uint8_t hash[32];

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "I:part_sha256",
                                     kwlist,
                                     &part_id);
    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_part_sha256(&package->pkg, hash, sizeof(hash), part_id);
    if (rc != BPAK_OK) {
        return bpak_raise(rc, "could not compute part hash");
    }

    return Py_BuildValue("y#", hash, (Py_ssize_t)sizeof(hash));
}

static PyObject *package_extract_file(PyObject *self, PyObject *args,
                                      PyObject *kwds)
{
    static char *kwlist[] = { "id", "filename", NULL };
    BPAKPackage *package = (BPAKPackage *)self;
    int rc;
    bpak_id_t part_id;
    PyObject *filename;

    if (package_check_open(package) < 0) {
        return NULL;
    }

    rc = PyArg_ParseTupleAndKeywords(args,
                                     kwds,
                                     "IO&:extract_file",
                                     kwlist,
                                     &part_id,
                                     &PyUnicode_FSConverter,
                                     &filename);
    if (!rc) {
        return NULL;
    }

    rc = bpak_pkg_extract_file(&package->pkg,
                               part_id,
                               PyBytes_AsString(filename));

    Py_DECREF(filename);

    if (rc != BPAK_OK) {
        return bpak_raise(rc, "could not extract part");
    }

    Py_RETURN_NONE;
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

static PyObject *package_get_digest(PyObject *self, void *Py_UNUSED(closure))
{
    return package_update_hash(self, NULL);
}

static PyObject *package_get_payload_hash(PyObject *self,
                                          void *Py_UNUSED(closure))
{
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *h = bpak_pkg_header(&package->pkg);
    Py_ssize_t hash_size;

    switch (h->hash_kind) {
    case BPAK_HASH_SHA256:
        hash_size = 32;
        break;
    case BPAK_HASH_SHA384:
        hash_size = 48;
        break;
    default:
        hash_size = sizeof(h->payload_hash);
        break;
    }

    return Py_BuildValue("y#", h->payload_hash, hash_size);
}

/* Integer fields of the header, the closure of their getters and setters */
struct header_field {
    const char *name;
    size_t offset;
    size_t size;
};

#define HEADER_FIELD(field)                                                    \
    {                                                                          \
        #field, offsetof(struct bpak_header, field),                           \
            sizeof(((struct bpak_header *)0)->field)                           \
    }

/* The getter and setter handle 8 and 32 bit fields */
static const struct header_field hash_kind_field = HEADER_FIELD(hash_kind);
static const struct header_field signature_kind_field =
    HEADER_FIELD(signature_kind);
static const struct header_field key_id_field = HEADER_FIELD(key_id);
static const struct header_field keystore_id_field = HEADER_FIELD(keystore_id);

static PyObject *package_get_header_field(PyObject *self, void *closure)
{
    const struct header_field *field = closure;
    BPAKPackage *package = (BPAKPackage *)self;
    const uint8_t *data =
        (const uint8_t *)bpak_pkg_header(&package->pkg) + field->offset;

    if (field->size == sizeof(uint8_t)) {
        return PyLong_FromUnsignedLong(*data);
    }

    /* The header is packed */
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return PyLong_FromUnsignedLong(value);
}

static int package_set_header_field(PyObject *self, PyObject *value,
                                    void *closure)
{
    const struct header_field *field = closure;
    BPAKPackage *package = (BPAKPackage *)self;
    uint8_t *data = (uint8_t *)bpak_pkg_header(&package->pkg) + field->offset;
    unsigned long long new_value;

    if (package_check_open(package) < 0) {
        return -1;
    }

    if (field->size == sizeof(uint8_t)) {
        if (py_to_uint(value, UINT8_MAX, field->name, &new_value) < 0) {
            return -1;
        }
        *data = (uint8_t)new_value;
    } else {
        if (py_to_uint(value, UINT32_MAX, field->name, &new_value) < 0) {
            return -1;
        }
        uint32_t value32 = (uint32_t)new_value;
        memcpy(data, &value32, sizeof(value32));
    }

    return package_write_header_or_raise(package, PyExc_OSError);
}

static PyObject *package_get_signature(PyObject *self, void *Py_UNUSED(closure))
{
    BPAKPackage *package = (BPAKPackage *)self;

    return Py_BuildValue("y#",
                         package->pkg.header.signature,
                         package->pkg.header.signature_sz);
}

static int package_set_signature(PyObject *self, PyObject *value,
                                 void *Py_UNUSED(closure))
{
    int rc;
    static const uint8_t empty_signature[1] = {0};
    uint8_t *signature_data;
    Py_ssize_t signature_sz;
    BPAKPackage *package = (BPAKPackage *)self;

    if (package_check_open(package) < 0) {
        return -1;
    }

    /* Handle clearing / del */
    if (value == NULL || value == Py_None) {
        rc = bpak_pkg_write_raw_signature(&package->pkg, empty_signature, 0);
        if (rc != BPAK_OK) {
            bpak_raise(rc, "failed to clear signature data");
            return -1;
        }
        return 0;
    }

    if (!PyBytes_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "type mismatch");
	    return -1;
    }

    if (PyBytes_AsStringAndSize(value, (char**)&signature_data, &signature_sz) < 0) {
        return -1;
    }

    if (signature_sz > BPAK_SIGNATURE_MAX_BYTES) {
        bpak_raise(-BPAK_SIZE_ERROR,
                   "signature is %zd bytes, the maximum is %d",
                   signature_sz,
                   BPAK_SIGNATURE_MAX_BYTES);
        return -1;
    }

    rc = bpak_pkg_write_raw_signature(&package->pkg,
                                      signature_data,
                                      signature_sz);

    if (rc != BPAK_OK) {
        bpak_raise(rc, "failed to set signature data");
        return -1;
    }

    return 0;
}

static PyObject *package_get_size(PyObject *self, void *Py_UNUSED(closure))
{
    BPAKPackage *package = (BPAKPackage *)self;
    return PyLong_FromSize_t(bpak_pkg_size(&package->pkg));
}

static PyObject *package_get_installed_size(PyObject *self,
                                            void *Py_UNUSED(closure))
{
    BPAKPackage *package = (BPAKPackage *)self;
    return PyLong_FromSize_t(bpak_pkg_installed_size(&package->pkg));
}

/* Append 'item' to 'list' and release it, 'item' may be NULL after a failed
 * allocation */
static int list_append_new(PyObject *list, PyObject *item)
{
    int rc;

    if (item == NULL) {
        return -1;
    }

    rc = PyList_Append(list, item);
    Py_DECREF(item);
    return rc;
}

static PyObject *package_get_parts(PyObject *self, void *Py_UNUSED(closure))
{
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *hdr = bpak_pkg_header(&package->pkg);
    PyObject *list = PyList_New(0);

    if (list == NULL) {
        return NULL;
    }

    bpak_foreach_part(hdr, p) {
        if (!p->id) {
            break;
        }

        PyObject *part = part_allocate(package, p->id);
        if (list_append_new(list, part) < 0) {
            Py_DECREF(list);
            return NULL;
        }
    }

    return list;
}

static PyObject *package_get_meta_list(PyObject *self,
                                       void *Py_UNUSED(closure))
{
    BPAKPackage *package = (BPAKPackage *)self;
    struct bpak_header *hdr = bpak_pkg_header(&package->pkg);
    PyObject *list = PyList_New(0);

    if (list == NULL) {
        return NULL;
    }

    bpak_foreach_meta(hdr, m) {
        if (!m->id) {
            break;
        }

        PyObject *meta = meta_allocate(package, m->id, m->part_id_ref);
        if (list_append_new(list, meta) < 0) {
            Py_DECREF(list);
            return NULL;
        }
    }

    return list;
}

static PyMethodDef package_methods[] = {
    { "close", package_close, METH_NOARGS, "Close package" },

    { "verify",
      KWARGS_METHOD(package_verify),
      METH_VARARGS | METH_KEYWORDS,
      "Verify package using a public key" },

    { "sign",
      KWARGS_METHOD(package_sign),
      METH_VARARGS | METH_KEYWORDS,
      "Sign package using a private key" },

    { "add_file",
      KWARGS_METHOD(package_add_file),
      METH_VARARGS | METH_KEYWORDS,
      "Create a new part object from a file" },

    { "add_key",
      KWARGS_METHOD(package_add_key),
      METH_VARARGS | METH_KEYWORDS,
      "Create a new part object from a key file" },

    { "add_meta",
      KWARGS_METHOD(package_add_meta),
      METH_VARARGS | METH_KEYWORDS,
      "Create a new metadata object" },

    { "get_part",
      KWARGS_METHOD(package_get_part),
      METH_VARARGS | METH_KEYWORDS,
      "Get a reference to a specific part object" },

    { "get_meta",
      KWARGS_METHOD(package_get_meta),
      METH_VARARGS | METH_KEYWORDS,
      "Get a reference to a specific metadata object" },

    { "update_hash",
      package_update_hash,
      METH_NOARGS,
      "Compute the payload hash and return the header hash" },

    { "write_header",
      package_write_header_method,
      METH_NOARGS,
      "Write the header to the file" },

    { "add_transport_meta",
      KWARGS_METHOD(package_add_transport_meta),
      METH_VARARGS | METH_KEYWORDS,
      "Add a transport encoder and decoder for a part" },

    { "delete_part",
      KWARGS_METHOD(package_delete_part),
      METH_VARARGS | METH_KEYWORDS,
      "Delete a part and, unless remove_meta is false, its meta data" },

    { "delete_all_parts",
      KWARGS_METHOD(package_delete_all_parts),
      METH_VARARGS | METH_KEYWORDS,
      "Delete all parts and, unless remove_meta is false, their meta data" },

    { "part_sha256",
      KWARGS_METHOD(package_part_sha256),
      METH_VARARGS | METH_KEYWORDS,
      "SHA-256 hash of a part" },

    { "extract_file",
      KWARGS_METHOD(package_extract_file),
      METH_VARARGS | METH_KEYWORDS,
      "Write the data of a part to a file" },

    /* For context manager use */
    { "__enter__", package_enter, METH_NOARGS, "" },
    { "__exit__", package_exit, METH_VARARGS, "" },

    { NULL, NULL, 0, NULL },
};

static PyGetSetDef package_getset[] = {
    { "digest",
      (getter)package_get_digest,
      (setter)NULL,
      "Package digest (header hash)",
      NULL },

    { "payload_hash",
      (getter)package_get_payload_hash,
      (setter)NULL,
      "Payload hash stored in the header",
      NULL },

    { "hash_kind",
      (getter)package_get_header_field,
      (setter)package_set_header_field,
      "Package hash kind (one of HASH_ constants)",
      (void *)&hash_kind_field },

    { "installed_size",
      (getter)package_get_installed_size,
      (setter)NULL,
      "The installed size of package",
      NULL },

    { "key_id",
      (getter)package_get_header_field,
      (setter)package_set_header_field,
      "Key ID used for signing/verification",
      (void *)&key_id_field },

    { "keystore_id",
      (getter)package_get_header_field,
      (setter)package_set_header_field,
      "Keystore ID used for signing",
      (void *)&keystore_id_field },

    { "signature",
      (getter)package_get_signature,
      (setter)package_set_signature,
      "Package signature (possibly empty if unsigned)",
      NULL },

    { "signature_kind",
      (getter)package_get_header_field,
      (setter)package_set_header_field,
      "Package signature kind (one of SIGN_ constants)",
      (void *)&signature_kind_field },

    { "size",
      (getter)package_get_size,
      (setter)NULL,
      "The actual size of the archive",
      NULL },

    { "parts",
      (getter)package_get_parts,
      (setter)NULL,
      "List of all parts in package",
      NULL },

    { "meta",
      (getter)package_get_meta_list,
      (setter)NULL,
      "List of all meta data in package",
      NULL },

    { NULL, NULL, NULL, NULL, NULL },
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
