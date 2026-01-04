#include "allocator.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Simple heap allocator with fault-detection support.
// Features:
//  - 40-byte alignment for all blocks.
//  - Header + footer metadata (footer mirrors header).
//  - Header checksum to detect partial metadata writes.
//  - Payload checksum to detect data corruption.
//  - Canary stores requested payload size.
//  - mm_write enforces "full-block writes only":
//    offset must be 0 and len must equal requested size.
// Any other write is treated as a brownout and quarantines the block.


#define ALIGNMENT 40
#define BLOCK_MAGIC 0xDEADBEEFu

#define BLOCK_FLAG_ALLOCATED  0x1u
#define BLOCK_FLAG_QUARANTINE 0x2u

#define FREE_PATTERN_LEN 5

// Block header/footer stored in the heap.
// Footer is a copy of the header at the end of the block.
typedef struct block_header_t {
  uint32_t magic;             // Block marker used to detect invalid headers.
  uint32_t flags;             // Allocation and quarantine flags.
  uint64_t size;              // Block size: header + payload + footer.
  uint64_t canary;            // Requested payload size (for write checks).
  uint64_t checksum;          // Metadata checksum (header fields only).
  uint64_t payload_checksum;  // Checksum of payload bytes.
} block_header_t;

typedef block_header_t block_footer_t;

// Global allocator metadata stored at the start of the heap.
// Tracks heap limits and the "free pattern" used to overwrite freed data.
typedef struct allocator_info {
  uint8_t *heap_start;                     // Start of entire heap region.
  size_t heap_size;                        // Total heap size in bytes.
  uint8_t free_pattern[FREE_PATTERN_LEN];  // Pattern for freed payload.
  uint8_t padding[19];                     // Pad to 40 bytes.
} allocator_info_t;

_Static_assert(sizeof(block_header_t) == ALIGNMENT,
               "block_header_t must be 40 bytes");
_Static_assert(sizeof(block_footer_t) == ALIGNMENT,
               "block_footer_t must be 40 bytes");
_Static_assert(sizeof(allocator_info_t) == ALIGNMENT,
               "allocator_info_t must be 40 bytes");

// Global allocator state.
static allocator_info_t *g_info = NULL;
static uint8_t *g_heap_start = NULL;
static size_t g_heap_size = 0;

// Return a canary value storing the requested payload size.
static inline uint64_t make_canary(size_t requested_size) {
  return (uint64_t)requested_size;
}

// Compute checksum over static metadata fields.
// This detects partial or inconsistent header writes.
static inline uint64_t compute_header_checksum(const block_header_t *h) {
  return ((uint64_t)h->magic ^ (uint64_t)h->flags ^ (uint64_t)h->size ^
          (uint64_t)h->canary);
}

// Round a size up to the required alignment.
static inline size_t align_up(size_t x) {
  size_t r = x % ALIGNMENT;
  return (r == 0) ? x : (x + (ALIGNMENT - r));
}

// Return pointer to the end of the managed heap region.
static inline uint8_t *heap_end(void) {
  return g_heap_start + g_heap_size;
}

// Compute the footer address for a given block header.
static block_footer_t *get_footer(block_header_t *h) {
  uint8_t *block_start = (uint8_t *)h;
  uint8_t *block_end = block_start + h->size;
  return (block_footer_t *)(block_end - sizeof(block_footer_t));
}

// Return pointer to the payload region for a given block header.
static uint8_t *get_payload(block_header_t *h) {
  return ((uint8_t *)h) + sizeof(block_header_t);
}

// Any change in payload bytes will change this value.
static uint64_t compute_payload_checksum(block_header_t *h) {
  uint8_t *start = get_payload(h);
  block_footer_t *f = get_footer(h);
  uint8_t *end = (uint8_t *)f;

  uint64_t acc = 0;
  for (uint8_t *p = start; p < end; ++p) {
    acc = (acc * 131) + *p;
  }
  return acc;
}

// Recompute and store the payload checksum in both header and footer.
// This is called after initialisation, free, and successful writes.
static void update_payload_checksum(block_header_t *h) {
  h->payload_checksum = compute_payload_checksum(h);
  block_footer_t *f = get_footer(h);
  f->payload_checksum = h->payload_checksum;
}

// Blocks are laid out back-to-back, so the next header is at h->size bytes.
static block_header_t *next_block(block_header_t *h) {
  if (h == NULL) {
    return NULL;
  }
  uint8_t *next = ((uint8_t *)h) + h->size;
  if (next >= heap_end()) {
    return NULL;
  }
  return (block_header_t *)next;
}

// Forward declaration for block validation.
static bool validate_block(block_header_t *h);

// Check whether a block is currently free and not quarantined.
static bool is_free(block_header_t *h) {
  return (h->flags & BLOCK_FLAG_ALLOCATED) == 0 &&
         (h->flags & BLOCK_FLAG_QUARANTINE) == 0;
}

// Validate header/footer and basic structural invariants.
// Used to detect corruption and partial writes before using a block.
static bool validate_block(block_header_t *h) {
  if (h == NULL || g_heap_start == NULL) {
    return false;
  }

  uint8_t *hs = (uint8_t *)h;

  // Header must be inside heap.
  if (hs < g_heap_start || hs + sizeof(block_header_t) > heap_end()) {
    return false;
  }

  // Magic must match expected marker.
  if (h->magic != BLOCK_MAGIC) {
    return false;
  }

  // Size must be plausible and aligned.
  size_t avail = (size_t)(heap_end() - hs);
  if (h->size < sizeof(block_header_t) + sizeof(block_footer_t)) {
    return false;
  }
  if (h->size % ALIGNMENT != 0) {
    return false;
  }
  if (h->size > avail) {
    return false;
  }

  // Header checksum must match metadata.
  if (h->checksum != compute_header_checksum(h)) {
    return false;
  }

  // Footer must also lie inside the heap.
  block_footer_t *f =
      (block_footer_t *)((uint8_t *)h + h->size - sizeof(block_footer_t));
  uint8_t *fs = (uint8_t *)f;
  if (fs < g_heap_start || fs + sizeof(block_footer_t) > heap_end()) {
    return false;
  }

  // Footer should mirror key header fields.
  if (f->magic != BLOCK_MAGIC || f->size != h->size ||
      f->checksum != h->checksum ||
      f->payload_checksum != h->payload_checksum) {
    return false;
  }

  return true;
}

// mm_init
// Initialise allocator state on top of the supplied heap region.
// - Reads the free pattern.
// - Places allocator_info at the front.
// - Creates a single large free block covering the rest.
int mm_init(uint8_t *heap, size_t heap_size) {
  if (heap == NULL) {
    return -1;
  }

  if (heap_size < sizeof(allocator_info_t) +
                      sizeof(block_header_t) +
                      sizeof(block_footer_t)) {
    return -1;
  }

  // Read FREE_PATTERN from the first bytes of the heap.
  uint8_t pattern[FREE_PATTERN_LEN];
  for (size_t i = 0; i < FREE_PATTERN_LEN; i++) {
    pattern[i] = heap[i];
  }

  // Place allocator_info at the start of the heap.
  g_info = (allocator_info_t *)heap;
  g_info->heap_start = heap;
  g_info->heap_size = heap_size;
  memcpy(g_info->free_pattern, pattern, FREE_PATTERN_LEN);

  // Block region begins after allocator_info.
  uint8_t *region_start = heap + sizeof(allocator_info_t);
  size_t region_size = heap_size - sizeof(allocator_info_t);

  // Down-align region size to a multiple of ALIGNMENT.
  size_t usable = region_size - (region_size % ALIGNMENT);
  if (usable < sizeof(block_header_t) + sizeof(block_footer_t)) {
    return -1;
  }

  g_heap_start = region_start;
  g_heap_size = usable;

  // Create a single initial free block.
  block_header_t *h = (block_header_t *)g_heap_start;
  h->magic = BLOCK_MAGIC;
  h->flags = 0;
  h->size = g_heap_size;
  h->canary = make_canary(0);  // No requested size for a free block.
  h->checksum = compute_header_checksum(h);

  block_footer_t *f = get_footer(h);
  *f = *h;

  // Initialise payload to the free pattern.
  uint8_t *payload_start = get_payload(h);
  uint8_t *payload_end = (uint8_t *)f;
  size_t payload_size = (size_t)(payload_end - payload_start);

  for (size_t i = 0; i < payload_size; i++) {
    payload_start[i] = g_info->free_pattern[i % FREE_PATTERN_LEN];
  }

  update_payload_checksum(h);
  return 0;
}

// mm_malloc
// Allocate an aligned block with at least "size" bytes of payload.
// Uses a simple first-fit search and splits large free blocks when possible.
// The canary stores the requested payload size for later write checks.
void *mm_malloc(size_t size) {
  if (size == 0 || g_heap_start == NULL) {
    return NULL;
  }

  size_t min_block_size =
      align_up(sizeof(block_header_t) + sizeof(block_footer_t));
  size_t needed = sizeof(block_header_t) + size + sizeof(block_footer_t);
  needed = align_up(needed);

  block_header_t *h = (block_header_t *)g_heap_start;

  while (h != NULL && (uint8_t *)h < heap_end()) {
    // Corrupt blocks are quarantined and scanning stops.
    if (!validate_block(h)) {
      h->flags |= BLOCK_FLAG_QUARANTINE;
      h->checksum = compute_header_checksum(h);
      break;
    }

    if (!is_free(h)) {
      h = next_block(h);
      continue;
    }

    size_t block_size = (size_t)h->size;
    if (block_size < needed) {
      h = next_block(h);
      continue;
    }

    size_t remaining = block_size - needed;

    // Use the entire block if the remainder would be too small.
    if (remaining < min_block_size) {
      h->flags |= BLOCK_FLAG_ALLOCATED;
      h->canary = make_canary(size);
      h->checksum = compute_header_checksum(h);

      block_footer_t *f = get_footer(h);
      *f = *h;

      update_payload_checksum(h);
      return get_payload(h);
    }

    // Split the free block into allocated and free parts.
    uint8_t *old_start = (uint8_t *)h;

    block_header_t *alloc_h = h;
    alloc_h->magic = BLOCK_MAGIC;
    alloc_h->flags = BLOCK_FLAG_ALLOCATED;
    alloc_h->size = (uint64_t)needed;
    alloc_h->canary = make_canary(size);
    alloc_h->checksum = compute_header_checksum(alloc_h);

    block_footer_t *alloc_f =
        (block_footer_t *)(old_start + needed - sizeof(block_footer_t));
    *alloc_f = *alloc_h;

    block_header_t *free_h = (block_header_t *)(old_start + needed);
    free_h->magic = BLOCK_MAGIC;
    free_h->flags = 0;
    free_h->size = (uint64_t)(block_size - needed);
    free_h->canary = make_canary(0);
    free_h->checksum = compute_header_checksum(free_h);

    block_footer_t *free_f =
        (block_footer_t *)(old_start + block_size - sizeof(block_footer_t));
    *free_f = *free_h;

    /* Initialise payload of the new free block. */
    uint8_t *free_payload_start = get_payload(free_h);
    uint8_t *free_payload_end = (uint8_t *)free_f;
    size_t free_payload_size =
        (size_t)(free_payload_end - free_payload_start);

    for (size_t i = 0; i < free_payload_size; i++) {
      free_payload_start[i] =
          g_info->free_pattern[i % FREE_PATTERN_LEN];
    }

    update_payload_checksum(free_h);
    update_payload_checksum(alloc_h);

    return get_payload(alloc_h);
  }

  return NULL;
}

// mm_free
// Free a previously allocated block.
// Steps:
//  - validate metadata;
//  - mark as free and reset canary;
//  - overwrite payload with free pattern;
//  - coalesce with adjacent free blocks;
//  - refresh payload checksum.
void mm_free(void *ptr) {
  if (ptr == NULL || g_heap_start == NULL) {
    return;
  }

  uint8_t *p = (uint8_t *)ptr;
  if (p < g_heap_start || p >= heap_end()) {
    return;
  }

  block_header_t *h = (block_header_t *)(p - sizeof(block_header_t));

  if (!validate_block(h)) {
    h->flags |= BLOCK_FLAG_QUARANTINE;
    h->checksum = compute_header_checksum(h);
    return;
  }

  if (!validate_block(h)) {
    return;
  }

  if ((h->flags & BLOCK_FLAG_ALLOCATED) == 0) {
    return;
  }

  h->flags &= ~BLOCK_FLAG_ALLOCATED;
  h->canary = make_canary(0);
  h->checksum = compute_header_checksum(h);

  block_footer_t *f = get_footer(h);
  *f = *h;

  uint8_t *payload_start = get_payload(h);
  uint8_t *payload_end = (uint8_t *)f;
  size_t payload_size = (size_t)(payload_end - payload_start);

  for (size_t i = 0; i < payload_size; i++) {
    payload_start[i] = g_info->free_pattern[i % FREE_PATTERN_LEN];
  }

  block_header_t *final_free = h;

  // Coalesce with right neighbour if it is a valid free block.
  block_header_t *next = next_block(h);
  if (next != NULL && validate_block(next) && is_free(next)) {
    uint64_t new_size = h->size + next->size;
    h->size = new_size;
    h->canary = make_canary(0);
    h->checksum = compute_header_checksum(h);

    block_footer_t *merged_footer =
        (block_footer_t *)((uint8_t *)h + new_size -
                           sizeof(block_footer_t));
    *merged_footer = *h;
  }

  // Search left neighbour by scanning from the start of the heap.
  block_header_t *prev = NULL;
  block_header_t *cur = (block_header_t *)g_heap_start;

  while (cur != NULL && (uint8_t *)cur < heap_end()) {
    if (!validate_block(cur)) {
      prev = NULL;
      break;
    }
    if (cur == h) {
      break;
    }
    prev = cur;
    cur = next_block(cur);
  }

  // Coalesce with left neighbour if it is free.
  if (prev != NULL && is_free(prev)) {
    uint64_t new_size = prev->size + h->size;
    prev->size = new_size;
    prev->canary = make_canary(0);
    prev->checksum = compute_header_checksum(prev);

    block_footer_t *merged_footer =
        (block_footer_t *)((uint8_t *)prev + new_size -
                           sizeof(block_footer_t));
    *merged_footer = *prev;

    final_free = prev;
  }

  update_payload_checksum(final_free);
}

// mm_read
// Safely read from an allocated block into buf.
// Validates metadata and payload checksum before copying.
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
  if (ptr == NULL || buf == NULL || len == 0 || g_heap_start == NULL) {
    return -1;
  }

  uint8_t *p = (uint8_t *)ptr;
  if (p < g_heap_start || p >= heap_end()) {
    return -1;
  }

  block_header_t *h = (block_header_t *)(p - sizeof(block_header_t));

  if (!validate_block(h)) {
    h->flags |= BLOCK_FLAG_QUARANTINE;
    h->checksum = compute_header_checksum(h);
    return -1;
  }

  if ((h->flags & BLOCK_FLAG_ALLOCATED) == 0 ||
      (h->flags & BLOCK_FLAG_QUARANTINE) != 0) {
    return -1;
  }

  uint8_t *payload_start = get_payload(h);
  block_footer_t *f = get_footer(h);
  uint8_t *payload_end = (uint8_t *)f;
  size_t payload_size = (size_t)(payload_end - payload_start);

  if (offset > payload_size || len > payload_size - offset) {
    return -1;
  }

  // Check payload integrity before reading.
  uint64_t actual = compute_payload_checksum(h);
  if (actual != h->payload_checksum) {
    h->flags |= BLOCK_FLAG_QUARANTINE;
    h->checksum = compute_header_checksum(h);

    block_footer_t *f_quar = get_footer(h);
    *f_quar = *h;
    return -1;
  }

  if ((h->flags & BLOCK_FLAG_ALLOCATED) == 0 ||
      (h->flags & BLOCK_FLAG_QUARANTINE) != 0) {
    return -1;
  }

  uint8_t *src = payload_start + offset;
  memcpy(buf, src, len);
  return (int)len;
}

// mm_write
// Safely write into an allocated block from src.
// Brownout rule:
//  - offset must be 0
//  - len must equal the requested payload size stored in canary
// Any deviation is treated as a partial write and the block is quarantined.
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
  if (ptr == NULL || src == NULL || len == 0 || g_heap_start == NULL) {
    return -1;
  }

  uint8_t *p = (uint8_t *)ptr;
  if (p < g_heap_start || p >= heap_end()) {
    return -1;
  }

  block_header_t *h = (block_header_t *)(p - sizeof(block_header_t));

  if (!validate_block(h)) {
    h->flags |= BLOCK_FLAG_QUARANTINE;
    h->checksum = compute_header_checksum(h);
    return -1;
  }

  // Verify payload integrity before modifying it.
  uint64_t actual = compute_payload_checksum(h);
  if (actual != h->payload_checksum) {
    h->flags |= BLOCK_FLAG_QUARANTINE;
    h->checksum = compute_header_checksum(h);

    block_footer_t *f_quar = get_footer(h);
    *f_quar = *h;
    return -1;
  }

  if ((h->flags & BLOCK_FLAG_ALLOCATED) == 0 ||
      (h->flags & BLOCK_FLAG_QUARANTINE) != 0) {
    return -1;
  }

  uint8_t *payload_start = get_payload(h);
  block_footer_t *f = get_footer(h);
  uint8_t *payload_end = (uint8_t *)f;
  size_t payload_size = (size_t)(payload_end - payload_start);

  if (offset > payload_size || len > payload_size - offset) {
    return -1;
  }

  size_t requested_size = (size_t)h->canary;

  // Enforce full-block writes:
  //  - requested_size must be sane,
  //  - offset must be zero,
  //  - len must equal requested_size.
  // Otherwise treat it as a brownout and quarantine the block.
  if (requested_size == 0 || requested_size > payload_size ||
      offset != 0 || len != requested_size) {
    h->flags |= BLOCK_FLAG_QUARANTINE;
    h->checksum = compute_header_checksum(h);

    block_footer_t *f_quar = get_footer(h);
    *f_quar = *h;
    return -1;
  }

  uint8_t *dst = payload_start + offset;
  memcpy(dst, src, len);

  update_payload_checksum(h);
  return (int)len;
}
