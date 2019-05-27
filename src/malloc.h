#ifndef MALLOC_H_INCLUDED
#define MALLOC_H_INCLUDED

#include "stdint.h"
#include "stddef.h"

#define PB_ENABLE_MALLOC 1

#define MALLOC_POOL_SIZE 500

struct malloc_ctx_s
{
    uint8_t malloc_pool[MALLOC_POOL_SIZE];
    uint16_t offset;
};
typedef struct malloc_ctx_s malloc_ctx_t;

extern malloc_ctx_t G_malloc_ctx;


void *realloc( void *ptr, size_t new_size );
void free(void *ptr);

#define ERR_POOL_OOM 0x6001

#endif