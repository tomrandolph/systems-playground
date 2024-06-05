#include <stdlib.h>
#include <sys/mman.h>

#include "alloc.h"
#ifdef DEBUG
#include <stdio.h>

#define debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#define perror(msg)
#endif // DEBUG

#define min_chunk_size sizeof(malloc_chunk)
#define max(a, b) (a > b ? a : b)
#define move_ptr(ptr, size) ((void *)((char *)(ptr) + (size)))

#define can_split_chunk(chunk, size) (chunk->size >= size + sizeof(malloc_chunk))
#define remove_chunk(chunk)              \
    {                                    \
        chunk->prev->next = chunk->next; \
        chunk->next->prev = chunk->prev; \
    }

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
#define PAGE_SIZE 4096

void expand_heap()
{
    debug("Expanding heap...");
    void *start_ptr = pages == NULL ? NULL : move_ptr(pages, PAGE_SIZE);
    void *addr = mmap(start_ptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }
    page *new_page = (page *)addr;
    new_page->next = pages;
    pages = new_page;
    num_pages += 1;
    debug("Heap expanded at %p\n", addr);
    mchunkptr chunk = (mchunkptr)move_ptr(addr, sizeof(page));
    chunk->size = PAGE_SIZE - sizeof(page) - sizeof(size_t);
    freelist_tail.prev->next = chunk;
    chunk->prev = freelist_tail.prev;
    freelist_tail.prev = chunk;
    chunk->next = &freelist_tail;
    debug("ok\n");
}
void *heap_alloc(size_t size)
{
    if (freelist_head.next == NULL)
    {
        debug("Initializing heap\n");
        freelist_head.next = &freelist_tail;
        freelist_tail.prev = &freelist_head;
        expand_heap();
    }
    if (freelist_head.next == &freelist_tail)
    {
        debug("No free chunks\n");
        expand_heap();
    }
    mchunkptr chunk = freelist_head.next;

    while (chunk->next != &freelist_tail && (chunk->size < size))
    {
        debug("Skipping chunk\n");
        chunk = chunk->next;
    }

    if (!can_split_chunk(chunk, size))
    {
        debug("Cannot split chunk. filling\n");
        remove_chunk(chunk);
        size_t *size_header = (size_t *)chunk;
        *size_header = chunk->size;
        return move_ptr(chunk, sizeof(size_t));
    }
    debug("Splitting chunk\n");

    mchunkptr chunk_prev = chunk->prev;
    mchunkptr chunk_next = chunk->next;
    size_t chunk_size = chunk->size;
    void *chunk_data = move_ptr(chunk, sizeof(size_t));

    size_t remaining_space = chunk_size - size;

    if (remaining_space <= sizeof(malloc_chunk))
    {
        debug("Out of memory: Remaining space %zu\n", remaining_space);
        return NULL;
    }
    size_t full_chunk_size = max(sizeof(size_t) + size, min_chunk_size);
    mchunkptr next_chunk = (mchunkptr)move_ptr(chunk, full_chunk_size);
    next_chunk->size = chunk_size - full_chunk_size;

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
    mchunkptr next_chunk = move_ptr(ptr, chunk_size);
    mchunkptr current = freelist_head.next;
    mchunkptr before = NULL;
    mchunkptr after = NULL;
    while (current != &freelist_tail)
    {
        if (current == next_chunk)
        {
            after = current;
        }
        if (move_ptr(current, current->size + sizeof(size_t)) == chunk)
        {
            debug("Found before\n");
            before = current;
        }
        current = current->next;
    }

    if (after != NULL)
    {
        remove_chunk(after);
        chunk->size += after->size + sizeof(size_t);
    }
    if (before != NULL)
    {
        remove_chunk(chunk); // extra work since we already added it
        before->size += chunk->size + sizeof(size_t);
    }
}

uint8_t check_is_free(void *ptr)
{
    mchunkptr current = freelist_head.next;
    while (current != &freelist_tail)
    {
        if ((void *)current == ptr)
        {
            return 1;
        }
        current = current->next;
    }
    return 0;
}
#define bool2str(b) (b ? "X" : "O")

void dump_heap()
{
    page *current_page = pages;
    while (current_page != NULL)
    {
        debug("Page: %p\n", current_page);
        void *end_of_page = move_ptr(current_page, PAGE_SIZE);
        size_t *current_chunk = (size_t *)move_ptr(current_page, sizeof(page));
        int i = 0;
        while ((void *)current_chunk < end_of_page)
        {
            if (i % 4 == 0)
            {
                debug("  ");
            }
            size_t current_chunk_size = *current_chunk;
            debug("Chunk: %ld, size: %zu, inuse: %s", ((char *)current_chunk - (char *)current_page), current_chunk_size, bool2str(!check_is_free(current_chunk)));
            current_chunk = move_ptr(current_chunk, current_chunk_size + sizeof(size_t));
            if (i % 4 == 3)
            {
                debug("\n");
            }
            else
            {
                debug(" | ");
            }
            i++;
        }
        if (i % 4 != 0)
        {
            debug("\n");
        }
        current_page = current_page->next;
    }
}

void dump_freelist()
{
    debug("Freelist\n  ");
    mchunkptr current = freelist_head.next;
    while (current != &freelist_tail)
    {
        debug("Chunk: %p, size: %zu | ", current, current->size);
        current = current->next;
    }
    debug("\n");
}
