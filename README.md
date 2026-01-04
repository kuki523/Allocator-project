# Allocator Project

This repository contains a custom memory allocator design. The allocator operates on a raw byte array (a provided heap region), enforces **40-byte alignment**, and includes **metadata + payload integrity checks** with a **quarantine** mechanism for corrupted blocks.

## Features

- **40-byte alignment:** All payload pointers returned by `mm_malloc` are aligned to 40 bytes.  
- **Block format:** `block_header_t | payload | block_footer_t`, with total block size rounded up to `ALIGNMENT = 40`.
- **Mirrored header/footer:** Header and footer share the same structure, mirroring integrity fields.   
- **Integrity & error detection:**
  - Metadata verification via `validate_block` (magic, size, alignment, header checksum, footer consistency).
  - Payload integrity verification via `compute_payload_checksum` prior to `mm_read` / `mm_write`.
  - Corrupted blocks are **quarantined** and isolated from future use. 
- **Allocation strategy:** First-fit search, with splitting of sufficiently large free blocks. 
- **Free strategy:** Coalesces adjacent free blocks and overwrites freed payload with `FREE_PATTERN`. 
- **Brownout/partial-write defense:** `mm_write` uses a **full-block write rule**; invalid writes trigger quarantine.

## High-level Design

### Heap layout

- The **first five bytes** of the heap store `FREE_PATTERN`.
- Immediately following is `allocator_info_t`, which stores heap size and the free-pattern sequence.
- The remainder of the heap stores a sequence of blocks:
  - `FREE`, `ALLOCATED`, or `QUARANTINED`.

### Block metadata (header/footer)

Both header and footer include:
- `magic`
- `flags`
- `size`
- `canary`
- `checksum`
- `payload_checksum`

### Quarantine behavior

Any mismatch detected in:
- metadata fields (magic/size/alignment/checksums/footer match), or
- payload checksum verification

results in the block being marked **QUARANTINED** and excluded from allocation or read/write attempts. 

## API

The allocator interface (declared in `allocator.h`) consists of:

- `mm_init(heap_ptr, heap_size)`
- `mm_malloc(size)`
- `mm_free(ptr)`
- `mm_read(ptr, offset, length, out_buf)`
- `mm_write(ptr, offset, length, in_buf)`

> Note: `mm_read` / `mm_write` validate payload integrity before processing; writes must satisfy the full-block write rule (offset=0 and length equals the payload size stored in canary), otherwise the block is quarantined. 

## Complexity & Trade-offs

- **Metadata overhead:** 80 bytes per block (40-byte header + 40-byte footer). 
- **Internal fragmentation:** Block size is computed as `align_up(40 + requested_size + 40)` to the next multiple of 40, which can be costly for small allocations. 
- **Time complexity:**
  - `mm_malloc`: O(n) first-fit scan through blocks in the worst case. 
  - `mm_free`: may scan from heap start to locate left neighbor in the worst case (O(n)). 
  - `mm_read`/`mm_write`: additional O(k) for payload checksum computation. 

The design prioritizes **integrity and early error detection** at the cost of some performance overhead. 

## Building & Testing

This project was tested using:
- `gcc` with warning and debug flags (`-Wall -Wextra -g`)
- a provided `runme.c` test harness for validating alignment and allocator behavior under different allocation/free/read/write scenarios.
- 
Typical workflow:
1. Build with your Makefile / gcc command line.
2. Run `runme.c` (or your own test driver) to:
   - check 40-byte alignment for returned payloads,
   - validate splitting/coalescing behavior,
   - trigger and observe quarantine behavior for invalid operations.

## References

- SlimGuard (Middleware ’19) 
- FreeGuard (CCS ’17) 
- LLVM Scudo Hardened Allocator
- AddressSanitizer (USENIX ATC ’12)
- DieHarder (CCS ’10)

---

## License

This repository is provided for educational purposes as part of COMP2221 coursework.
