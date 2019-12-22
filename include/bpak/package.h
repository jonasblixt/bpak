#ifndef INCLUDE_BPAK_PACKAGE_H_
#define INCLUDE_BPAK_PACKAGE_H_

#include <bpak/bpak.h>

struct bpak_package
{
};

/*
int bpak_pkg_open_file(struct bpak_package *pkg, ...);
int bpak_pkg_open_blockdevice(struct bpak_package *pkg, ...);
int bpak_pkg_close(struct bpak_package *pkg);

Add/Modify stuff:
int bpak_pkg_add_file(struct bpak_package *pkg, ...);
int bpak_pkg_add_merkle(struct bpak_package *pkg, ...);
int bpak_pkg_add_meta(struct bpak_package *pkg, ...);
int bpak_pkg_transport_encode(struct bpak_package *pkg, ...);
int bpak_pkg_transport_decode(struct bpak_package *pkg, ...);
int bpak_pkg_transport_done(struct bpak_package *pkg, ...);
int bpak_pkg_sign(struct bpak_package *pkg, ...);

Read:
int bpak_pkg_verify(struct bpak_package *pkg, ...);

*/
#endif  // INCLUDE_BPAK_PACKAGE_H_
