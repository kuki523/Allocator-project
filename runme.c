#include "allocator.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Simple test driver for the custom allocator.
// Behaviour:
// - Allocates a 4 KiB backing store and calls mm_init().
// - Performs a few mm_malloc/mm_free calls.
// - Exercises mm_read/mm_write on a small block.
// - Prints pointer values and alignment information.

int main(void) {
  // Size of the raw heap region we will manage.
  size_t heap_size = 4096;

  // Backing store for the allocator.
  uint8_t *heap = malloc(heap_size);
  if (!heap) {
    fprintf(stderr, "Error: could not allocate heap\n");
    return 1;
  }

  // Initialise the allocator on top of the heap buffer.
  int res = mm_init(heap, heap_size);
  if (res != 0) {
    fprintf(stderr, "mm_init failed with code %d\n", res);
    free(heap);
    return 1;
  }

  printf("mm_init succeeded!\n");

  // Basic allocation and free tests.
  void *a = mm_malloc(100);
  void *b = mm_malloc(200);
  printf("a = %p\n", a);
  printf("b = %p\n", b);

  mm_free(a);
  mm_free(b);

  // Allocate again after frees to check coalescing behaviour.
  void *c = mm_malloc(250);
  printf("c = %p\n", c);

  printf("\n--- mm_read/mm_write test ---\n");

  // Allocate a block for read/write testing.
  void *x = mm_malloc(64);

  // Message to write into the allocated block.
  char msg[] = "hello allocator!";
  char buf[32] = {0};

  // Attempt to write msg into x at offset 0.
  // With the brownout rules, mm_write may reject partial writes if
  // len does not match the requested size passed to mm_malloc().
  int w = mm_write(x, 0, msg, sizeof(msg));
  printf("mm_write returned %d\n", w);

  // Read back from the same block into buf.
  int r = mm_read(x, 0, buf, sizeof(msg));
  printf("mm_read returned %d\n", r);

  printf("read back = %s\n", buf);

  // Alignment checks: all payload pointers should be 40-byte aligned.
  printf("a %% 40 = %ld\n", (long)((uintptr_t)a % 40));
  printf("b %% 40 = %ld\n", (long)((uintptr_t)b % 40));
  printf("c %% 40 = %ld\n", (long)((uintptr_t)c % 40));

  // Release the backing store; allocator state becomes invalid.
  free(heap);
  return 0;
}
