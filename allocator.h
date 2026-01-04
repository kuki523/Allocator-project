#ifndef ALLOCATOR_H
#define ALLOCATOR_H
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint8_t, uint32_t, uint64_t, uintptr_t

// Allocator API

// Start the heap
int mm_init(uint8_t *heap, size_t heap_size);

// Allocate memory
void *mm_malloc(size_t size);

// Free memory
void mm_free(void *ptr);

// Safe read
int mm_read(void *ptr, size_t offset, void *buf, size_t len);

// Safe write
int mm_write(void *ptr, size_t offset, const void *src, size_t len);

#endif  // ALLOCATOR_H
