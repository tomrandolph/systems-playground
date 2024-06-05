#ifndef ALLOC_H
#include <stdlib.h>

#define ALLOC_H
void heap_free(void *ptr);
void *heap_alloc(size_t size);
#ifdef DEBUG
void dump_heap();
void dump_freelist();

#endif
#endif // ALLOC_H
