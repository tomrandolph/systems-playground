# Malloc

## Goals

1. Understand heap allocations/de-allocations
2. Learn C toolchain (GCC, make)
3. Increase familiarity in C

## Sources

- https://www.gnu.org/software/libc/manual/html_node/The-GNU-Allocator.html
- https://www.gnu.org/software/libc/manual/html_node/Replacing-malloc.html
- https://sourceware.org/glibc/wiki/MallocInternals
- https://github.com/lattera/glibc/blob/master/malloc/malloc.c

## Notes

glibc's `malloc` implementation will allocate either in chunks of memory from multiple large continuous "arenas" for smaller objects

<!-- how are these arenas allocated? mmap? -->

Larger objects will be allocated with isolated chunks of memory directly allocated from the system with `mmap` and are not reused and instead freed back to the system upon a call to `free`

### Building blocks

**Arena**: Holds reference to one or more heap and a free list for the heaps. Shared amongst one or more threads. Main arena is in the program heap, others are mmap'ed
**Heap**: Block of memory to be chunked and allocated to (one chunk at a time) within exactly one arena

<!-- Why is the "heap" called a heap? does it you a heap datastructure internally? -->

**Chunk**: A arbitrary\* sized block of memory within a heap that can be allocated to a program or freed from a program (chunks can be merged upon free)

#### Chunks

https://sourceware.org/glibc/wiki/MallocInternals?action=AttachFile&do=get&target=MallocInternals-chunk-inuse.svg
https://sourceware.org/glibc/wiki/MallocInternals?action=AttachFile&do=get&target=MallocInternals-chunk-free.svg

Minsize: `4*sizeof(void*)`
3 Flags

### Arenas

Each has a mutex. As more threads are active, more arenas created to reduce contention

# My Design

No arenas?
No mutex?
All memory mmap'd?
