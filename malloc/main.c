#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "alloc.h"

#define assert(cond, msg)       \
    {                           \
        if (!(cond))            \
        {                       \
            perror(msg);        \
            exit(EXIT_FAILURE); \
        }                       \
    }

#define PVAL 10
#define QVAL 20

int main()
{
    int i = 0;

    typedef long long to_allocate;
    uint64_t size = sizeof(to_allocate);
    while (i < 30)
    {
        printf("Iteration %d\n", i);
        to_allocate *p = heap_alloc(size);
        if (p == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }

        to_allocate *q = heap_alloc(size);
        if (q == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }

        printf("p: %p, q: %p\n", p, q);
        *p = PVAL;
        *q = QVAL;

        i++;
        if (*p + *q != PVAL + QVAL)
        {
            printf("Memory corrupted\n");
            break;
        }
        if (i % 2 == 0)
        {
            printf("Freeing %zu\n", size);
            heap_free(p);
        }
        if (i % 4 == 0)
        {
            printf("Freeing %zu\n", size);
            heap_free(q);
        }
        if (i % 8)
        {
            size += 8;
            printf("Increasing size to %zu\n", size);
        }
    }
#ifdef DEBUG
    dump_heap();
    dump_freelist();
#endif

    return EXIT_SUCCESS;
}
