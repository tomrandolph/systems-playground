#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
struct malloc_chunk
{
    size_t size;
    bool inuse;
    struct malloc_chunk *next;
    struct malloc_chunk *prev;
} typedef malloc_chunk;

typedef malloc_chunk *mchunkptr;

static void *heap = NULL;
static size_t heap_size = 0;
static mchunkptr freelist;
static mchunkptr all_chunks;
#define HEAP_SIZE 4096

#define fail(msg)           \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    }

#define move_ptr(ptr, size) ((void *)((char *)(ptr) + (size)))

void init_heap()
{
    void *addr = mmap(heap, HEAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        fail("mmap");
    heap = addr;
    heap_size += HEAP_SIZE;
    printf("Heap initialized at %p\n", heap);
    mchunkptr chunk = (mchunkptr)heap;
    chunk->size = HEAP_SIZE - sizeof(malloc_chunk);
    chunk->next = NULL;
    freelist = chunk;
    all_chunks = chunk;
    printf("ok\n");
}

void *heap_alloc(size_t size)
{
    // Basic algorithm
    // 1. Search freelist for chunk of size >= size
    // 2. If found, split the chunk, update the freelist and return the address
    // 3. If not found, request more memory from the OS
    // 4. Go to step 2
    if (heap == NULL)
    {
        printf("Uninitialized heap\n");
        init_heap();
    }
    mchunkptr chunk = freelist;
    // printf("chunk: %p\n", chunk);
    size_t chunk_size = chunk->size;
    // printf("chunk size: %u, size: %d remainder: %d\n", chunk_size, size, chunk_size - size);
    size_t required_size = size + sizeof(malloc_chunk);
    if (chunk_size < required_size)
    {
        printf("Not enough memory. remaining: %zu required: %zu+%zu=%zu\n", chunk_size, size, sizeof(malloc_chunk), required_size);
        return NULL;
    }

    void *data = move_ptr(chunk, sizeof(malloc_chunk));
    chunk->size = size;
    chunk->inuse = true;

    mchunkptr next_chunk = (mchunkptr)move_ptr(data, size);
    next_chunk->size = chunk_size - required_size;
    next_chunk->prev = chunk;
    next_chunk->inuse = false;

    chunk->next = next_chunk;
    next_chunk->next = NULL;
    next_chunk->prev = chunk;

    freelist = next_chunk;
    return data;
}

void heap_free(void *ptr)
{
    mchunkptr chunk = (mchunkptr)move_ptr(ptr, -sizeof(malloc_chunk));
    chunk->inuse = false;
}

#define PVAL 10
#define QVAL 20
#define bool2str(b) (b ? "X" : "O")
void dump_heap()
{
    printf("Heap dump\n");
    mchunkptr chunk = all_chunks;
    int i = 1;
    while (chunk != NULL)
    {
        printf("| %s %zu ", bool2str(chunk->inuse), chunk->size);
        if (!(i % 8))
            printf("\n");
        chunk = chunk->next;
        i += 1;
    }
    printf("\n");
}

int main()
{
    int i = 1;
    u_int64_t total_allocated = 0;

    while (1)
    {
        int *p = heap_alloc(sizeof(int));
        int *q = heap_alloc(sizeof(int));
        total_allocated += sizeof(int) * 2;
        if (p == NULL || q == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }
        printf("p: %p, q: %p\n", p, q);
        *p = PVAL;
        *q = QVAL;
        if ((i % 3) == 0)
        {
            heap_free(p);
            heap_free(q);
        }
        i++;
        // printf("(%d) p + q = %d. expected: %d. Success: %s\n", i, *p + *q, PVAL + QVAL, *p + *q == PVAL + QVAL ? "true" : "false");
    }
    dump_heap();
    printf("Total allocated: %lu bytes using %zu with %.2f%%\n", total_allocated, HEAP_SIZE, 100 * (float)total_allocated / HEAP_SIZE);
    return EXIT_SUCCESS;
}
