#include "malloc.h"
#include "os.h"

malloc_ctx_t G_malloc_ctx;


void *realloc( void *ptr, size_t new_size ){

    PRINTF("Try realloc for %p / %d - pool offset: %u\n", ptr, new_size, G_malloc_ctx.offset);

    if(G_malloc_ctx.offset + new_size > MALLOC_POOL_SIZE){
        PRINTF("Error, allocation pool out of memory\n");
        return NULL;
    }

    G_malloc_ctx.offset += new_size;

    return G_malloc_ctx.malloc_pool+G_malloc_ctx.offset-new_size;
}

void free(void *ptr){
    PRINTF("Free: %p\n", ptr);
}