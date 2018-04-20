#ifndef X16RW_H
#define X16RW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void x16rw_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
