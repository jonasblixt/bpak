#ifndef SRC_BPAK_TOOL_H_
#define SRC_BPAK_TOOL_H_

#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/file.h>
#include <bpak/merkle.h>
#include <bpak/alg.h>
#include <bpak/utils.h>
#include <bpak/keystore.h>

int action_add(int argc, char **argv);
int action_show(int argc, char **argv);
int action_create(int argc, char **argv);
int action_sign(int argc, char **argv);
int action_verify(int argc, char **argv);
int action_generate(int argc, char **argv);
int action_transport(int argc, char **argv);
int action_set(int argc, char **argv);
int action_compare(int argc, char **argv);

void print_usage(void);
void print_add_usage(void);
void print_create_usage(void);
void print_common_usage(void);
void print_version(void);
void print_verify_usage(void);
void print_sign_usage(void);
void print_show_usage(void);
void print_generate_usage(void);
void print_transport_usage(void);
void print_compare_usage(void);
void print_set_usage(void);

int bpak_get_verbosity(void);
void bpak_inc_verbosity(void);

#endif
