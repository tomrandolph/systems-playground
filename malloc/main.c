#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
struct malloc_chunk
{
    size_t size;
    struct malloc_chunk *next;
    struct malloc_chunk *prev;
} typedef malloc_chunk;

typedef malloc_chunk *mchunkptr;

static size_t heap_size = 0;

static malloc_chunk free_list_tail =
    {
        .size = 0,
        .next = NULL,
        .prev = NULL};
static malloc_chunk free_list_head =
    {
        .size = 0,
        .next = NULL,
        .prev = NULL};

#define can_split_chunk(chunk, size) (chunk->size >= size + sizeof(malloc_chunk))
#define remove_chunk(chunk)              \
    {                                    \
        chunk->prev->next = chunk->next; \
        chunk->next->prev = chunk->prev; \
    }
#define HEAP_SIZE 4096

#define assert(cond, msg) \
    {                     \
        if (!(cond))      \
            fail(msg);    \
    }

#define fail(msg)           \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    }

#define move_ptr(ptr, size) ((void *)((char *)(ptr) + (size)))

void expand_heap()
{
    static void *heap = NULL;
    printf("Expanding heap...");
    void *start_ptr = heap == NULL ? NULL : move_ptr(heap, heap_size);
    void *addr = mmap(start_ptr, HEAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (heap == NULL)
        heap = addr;
    if (addr == MAP_FAILED)
        fail("mmap");
    heap_size += HEAP_SIZE;
    printf("Heap expanded at %p\n", addr);
    mchunkptr chunk = (mchunkptr)addr;
    chunk->size = HEAP_SIZE - sizeof(size_t);
    free_list_tail.prev->next = chunk;
    chunk->prev = free_list_tail.prev;
    free_list_tail.prev = chunk;
    chunk->next = &free_list_tail;
    printf("ok\n");
}

void *heap_alloc(size_t size)
{
    if (free_list_head.next == NULL)
    {
        printf("Initializing heap\n");
        free_list_head.next = &free_list_tail;
        free_list_tail.prev = &free_list_head;
        expand_heap();
    }
    if (free_list_head.next == &free_list_tail)
    {
        printf("No free chunks\n");
        expand_heap();
    }
    mchunkptr chunk = free_list_head.next;

    while (chunk->next != &free_list_tail && (chunk->size < size))
    {
        printf("Skipping chunk\n");
        chunk = chunk->next;
    }

    if (!can_split_chunk(chunk, size))
    {
        printf("Cannot split chunk. filling\n");
        remove_chunk(chunk);
        size_t *size_header = (size_t *)chunk;
        *size_header = chunk->size;
        return move_ptr(chunk, sizeof(size_t));
    }
    printf("Splitting chunk\n");

    mchunkptr chunk_prev = chunk->prev;
    mchunkptr chunk_next = chunk->next;
    size_t chunk_size = chunk->size;
    void *chunk_data = move_ptr(chunk, sizeof(size_t));

    mchunkptr next_chunk = (mchunkptr)move_ptr(chunk_data, size);
    size_t remaining_space = chunk_size - size;

    if (remaining_space <= sizeof(malloc_chunk))
    {
        printf("Out of memory: Remaining space %zu\n", remaining_space);
        return NULL;
    }
    next_chunk->size = chunk_size - size - sizeof(size_t); // TODO use pointer arithmetic instead?

    next_chunk->prev = chunk_prev;
    next_chunk->next = chunk_next;
    chunk_prev->next = next_chunk;
    chunk_next->prev = next_chunk;

    size_t *size_header = (size_t *)chunk;
    *size_header = chunk_size;
    return chunk_data;
}

#define PVAL 10
#define QVAL 20
#define bool2str(b) (b ? "X" : "O")

int main()
{
    int i = 1;
    u_int64_t total_allocated = 0;

    while (i < 4096)
    {
        printf("Iteration %d\n", i);
        int *p = heap_alloc(sizeof(int));
        if (p == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }
        total_allocated += sizeof(int);
        int *q = heap_alloc(sizeof(int));
        if (q == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }
        total_allocated += sizeof(int);
        printf("p: %p, q: %p\n", p, q);
        *p = PVAL;
        *q = QVAL;

        i++;
        printf("(%d) p + q = %d. expected: %d. Success: %s\n", i, *p + *q, PVAL + QVAL, *p + *q == PVAL + QVAL ? "true" : "false");
        if (*p + *q != PVAL + QVAL)
        {
            printf("Memory corrupted\n");
            break;
        }
    }

    printf("Total allocated: %llu bytes using %zu with %.2f%%\n", total_allocated, heap_size, 100 * (float)total_allocated / heap_size);
    return EXIT_SUCCESS;
}
