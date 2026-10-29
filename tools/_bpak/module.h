#ifndef BPAK_PYTHON_MODULE_H_
#define BPAK_PYTHON_MODULE_H_

#include <bpak/pkg.h>

#define membersof(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef struct {
    PyObject_HEAD
    struct bpak_package pkg;
} BPAKPackage;

typedef struct {
    PyObject_HEAD
    BPAKPackage *package;
    bpak_id_t part_id;
} BPAKPart;

typedef struct {
    PyObject_HEAD
    BPAKPackage *package;
    bpak_id_t meta_id;
    bpak_id_t part_ref;
} BPAKMeta;

extern PyTypeObject BPAKPackageType;
extern PyTypeObject BPAKPartType;
extern PyTypeObject BPAKMetaType;

/* Base class of all bpak exceptions, 'bpak.Error' */
extern PyObject *BPAKPackageError;

int package_write_header(BPAKPackage *package, bool update_hash);

/* Raise ValueError and return -1 if the package is closed */
int package_check_open(BPAKPackage *package);

/* The header of a part or meta data, or NULL with KeyError set */
struct bpak_part_header *package_find_part(BPAKPackage *package,
                                           bpak_id_t part_id);
struct bpak_meta_header *package_find_meta(BPAKPackage *package,
                                           bpak_id_t meta_id,
                                           bpak_id_t part_ref);

PyObject *part_allocate(BPAKPackage *package, bpak_id_t part_id);
PyObject *meta_allocate(BPAKPackage *package, bpak_id_t meta_id, bpak_id_t part_ref);

/* Convert 'value', the new value of the attribute 'name', to an unsigned
 * integer of at most 'max'. Raises TypeError when the attribute is deleted
 * ('value' is NULL) or 'value' is not an int, and OverflowError when it is
 * negative or larger than 'max'. Returns 0 or -1 with an exception set. */
int py_to_uint(PyObject *value,
               unsigned long long max,
               const char *name,
               unsigned long long *out);

/* Create the exception classes and add them to the module */
int bpak_exceptions_init(PyObject *module);

/* Raise the exception that matches the bpak error code 'rc', with the message
 * '<fmt>: <bpak_error_string(rc)>'. Always returns NULL. */
PyObject *bpak_raise(int rc, const char *fmt, ...);

#endif
