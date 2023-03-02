#ifndef PYTHONWRAPPER_PYTHONWRAPPER_H_
#define PYTHONWRAPPER_PYTHONWRAPPER_H_

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

extern PyObject *BPAKPackageError;

int package_write_header(BPAKPackage *package, bool update_hash);

PyObject *part_allocate(BPAKPackage *package, bpak_id_t part_id);
PyObject *meta_allocate(BPAKPackage *package, bpak_id_t meta_id, bpak_id_t part_ref);

#endif
