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
struct page
{
    struct page *next;
} typedef page;

static size_t num_pages = 0;

static malloc_chunk freelist_tail =
    {
        .size = 0,
        .next = NULL,
        .prev = NULL};
static malloc_chunk freelist_head =
    {
        .size = 0,
        .next = NULL,
        .prev = NULL};
static page *pages = NULL;

#define min_chunk_size sizeof(malloc_chunk)
#define max(a, b) (a > b ? a : b)

#define can_split_chunk(chunk, size) (chunk->size >= size + sizeof(malloc_chunk))
#define remove_chunk(chunk)              \
    {                                    \
        chunk->prev->next = chunk->next; \
        chunk->next->prev = chunk->prev; \
    }
#define PAGE_SIZE 4096

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
    printf("Expanding heap...");
    void *start_ptr = pages == NULL ? NULL : move_ptr(pages, PAGE_SIZE);
    void *addr = mmap(start_ptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        fail("mmap");
    page *new_page = (page *)addr;
    new_page->next = pages;
    pages = new_page;
    num_pages += 1;
    printf("Heap expanded at %p\n", addr);
    mchunkptr chunk = (mchunkptr)move_ptr(addr, sizeof(page));
    chunk->size = PAGE_SIZE - sizeof(page) - sizeof(size_t);
    freelist_tail.prev->next = chunk;
    chunk->prev = freelist_tail.prev;
    freelist_tail.prev = chunk;
    chunk->next = &freelist_tail;
    printf("ok\n");
}

void *heap_alloc(size_t size)
{
    if (freelist_head.next == NULL)
    {
        printf("Initializing heap\n");
        freelist_head.next = &freelist_tail;
        freelist_tail.prev = &freelist_head;
        expand_heap();
    }
    if (freelist_head.next == &freelist_tail)
    {
        printf("No free chunks\n");
        expand_heap();
    }
    mchunkptr chunk = freelist_head.next;

    while (chunk->next != &freelist_tail && (chunk->size < size))
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

    size_t remaining_space = chunk_size - size;

    if (remaining_space <= sizeof(malloc_chunk))
    {
        printf("Out of memory: Remaining space %zu\n", remaining_space);
        return NULL;
    }
    size_t full_chunk_size = max(sizeof(size_t) + size, min_chunk_size);
    mchunkptr next_chunk = (mchunkptr)move_ptr(chunk, full_chunk_size);
    next_chunk->size = chunk_size - full_chunk_size; // TODO use pointer arithmetic instead?

    next_chunk->prev = chunk_prev;
    next_chunk->next = chunk_next;
    chunk_prev->next = next_chunk;
    chunk_next->prev = next_chunk;

    size_t *size_header = (size_t *)chunk;
    *size_header = full_chunk_size - sizeof(size_t);
    return chunk_data;
}

void heap_free(void *ptr)
{
    mchunkptr chunk = (mchunkptr)move_ptr(ptr, -sizeof(size_t));
    size_t chunk_size = *(size_t *)chunk;
    chunk->size = chunk_size; // TODO probably not needed due to struct ordering
    mchunkptr first = freelist_head.next;
    chunk->next = first;
    chunk->prev = &freelist_head;
    first->prev->next = chunk;
    first->prev = chunk;
    assert((void *)chunk > (void *)pages, "Invalid pointer");
    assert((void *)chunk->next > (void *)pages, "Invalid next pointer");
}

bool check_is_free(void *ptr)
{
    mchunkptr current = freelist_head.next;
    while (current != &freelist_tail)
    {
        if ((void *)current == ptr)
        {
            return true;
        }
        current = current->next;
    }
    return false;
}
#define bool2str(b) (b ? "X" : "O")

void dump_heap()
{
    page *current_page = pages;
    while (current_page != NULL)
    {
        printf("Page: %p\n", current_page);
        void *end_of_page = move_ptr(current_page, PAGE_SIZE);
        size_t *current_chunk = (size_t *)move_ptr(current_page, sizeof(page));
        int i = 0;
        while ((void *)current_chunk < end_of_page)
        {
            if (i % 4 == 0)
            {
                printf("  ");
            }
            size_t current_chunk_size = *current_chunk;
            printf("Chunk: %d, size: %zu, inuse: %s", ((char *)current_chunk - (char *)current_page), current_chunk_size, bool2str(!check_is_free(current_chunk)));
            current_chunk = move_ptr(current_chunk, current_chunk_size + sizeof(size_t));
            if (i % 4 == 3)
            {
                printf("\n");
            }
            else
            {
                printf(" | ");
            }
            i++;
        }
        if (i % 4 != 0)
        {
            printf("\n");
        }
        current_page = current_page->next;
    }
}

void dump_freelist()
{
    printf("Freelist\n  ");
    mchunkptr current = freelist_head.next;
    while (current != &freelist_tail)
    {
        printf("Chunk: %d, size: %zu | ", current, current->size);
        current = current->next;
    }
    printf("\n");
}

#define PVAL 10
#define QVAL 20

// int main()
// {
//     char *p = heap_alloc(3);
//     // *p = "12345678901234568901234";
//     dump_heap();
//     dump_freelist();
//     printf("p: %p, %u ----------------\n", p, sizeof(size_t));
//     heap_free(p);
//     dump_heap();
//     dump_freelist();
//     return EXIT_SUCCESS;
// }

int main()
{
    int i = 0;
    u_int64_t total_allocated = 0;
    typedef long long to_allocate;
    while (i < 4096)
    {
        printf("Iteration %d\n", i);
        to_allocate *p = heap_alloc(sizeof(to_allocate));
        if (p == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }
        total_allocated += sizeof(to_allocate);
        to_allocate *q = heap_alloc(sizeof(to_allocate));
        if (q == NULL)
        {
            printf("Failed to allocate memory\n");
            break;
        }
        total_allocated += sizeof(to_allocate);
        printf("p: %p, q: %p\n", p, q);
        *p = PVAL;
        *q = QVAL;

        i++;
        printf("(%d) p + q = %lld. expected: %d. Success: %s\n", i, *p + *q, PVAL + QVAL, *p + *q == PVAL + QVAL ? "true" : "false");
        if (*p + *q != PVAL + QVAL)
        {
            printf("Memory corrupted\n");
            break;
        }
        if (i % 2 == 0)
        {
            heap_free(p);
            total_allocated -= sizeof(to_allocate);
        }
        if (i % 4 == 0)
        {
            heap_free(q);
            total_allocated -= sizeof(to_allocate);
        }
    }
    dump_heap();

    printf("Total allocated: %llu bytes using %zu with %.2f%%\n", total_allocated, num_pages * PAGE_SIZE, 100 * (float)total_allocated / (num_pages * PAGE_SIZE));
    return EXIT_SUCCESS;
}
