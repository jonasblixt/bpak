#ifndef LIB_SAIS_H_
#define LIB_SAIS_H_

#include <stdint.h>

int sais32(const uint8_t *t_p, int32_t *sa_p, int32_t n);
int sais64(const uint8_t *t_p, int64_t *sa_p, int64_t n);

#endif
