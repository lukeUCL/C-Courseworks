#define CS0019_DISABLE 1
#include "cs0019.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// global counters for stats
static unsigned long long g_nactive = 0;
static unsigned long long g_ntotal = 0;
static unsigned long long g_nfail = 0;
static unsigned long long g_active_size = 0;
static unsigned long long g_total_size = 0;
static unsigned long long g_fail_size = 0;
static char *g_heap_min = NULL;
static char *g_heap_max = NULL;

// linked list for active allocaitons
static struct block_metadata *g_active_list = NULL;

struct block_metadata {
  void *ptr;
  size_t size;
  unsigned int status;
  int line;
  const char *file;
  struct block_metadata *next;
};

#define CANARY 0xFF

// 10000 diff file / line parirs
#define MAX_SITES 10000

struct allocation_sites {
  const char *file;
  int line;
  size_t allocated_bytes;
};

static struct allocation_sites sites[MAX_SITES];
static int site_count = 0;
static unsigned long long total_allocated_bytes = 0;

// site is a line/file pair; each time we alloc, we update alloc stats for this site
// so we can use in heavy hitter report.
static int find_site_index(const char *file, int line) {
  // comparisons over site and line, if we have already seen this site return index,
  // else we will make a new one
  for (int i = 0; i < site_count; i++) {
    if (sites[i].file == file && sites[i].line == line) {
      return i;
    }
  }

  if (site_count < MAX_SITES) {
    sites[site_count].file = file;
    sites[site_count].line = line;
    sites[site_count].allocated_bytes = 0;
    return site_count++;
  }
  return -1;
}

/// cs0019_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then cs0019_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

// from test2, test3 easy to see that malloc stats not updated 
void *cs0019_malloc(size_t sz, const char *file, int line) {
  (void)file, (void)line; // avoid uninitialized variable warnings

  // use idea from lecture to track size of an allocated block
  // i.e add padding that holds size

  // cw says we should catch cases where memory is written directly after block
  // so lets just use 1 byte for canary

  // for test 36, we need to store metadata and payload separately, so metadata isnt restored

  // check for overflow, account for canary
  if (sz > SIZE_MAX -8) { 
        g_nfail++;
        g_fail_size += sz;
        return NULL;
    }

  size_t payloadSize = (sz + 1 + 7) & ~7;
  void *payload = base_malloc(payloadSize);

  // update failures
  if (!payload) {
    g_nfail++;
    g_fail_size += sz;
    return NULL;
  }

  // set canary
  unsigned char *canary = (unsigned char *)payload + sz;
  *canary = CANARY;

  // now, allocate metadata separately
  struct block_metadata *metadata = base_malloc(sizeof(struct block_metadata));
  if (!metadata) {
    base_free(payload);
    g_nfail++;
    g_fail_size += sz;
    return NULL;
  }
  metadata->ptr = payload;
  metadata->size = sz;
  metadata->status = 1; // 1 for allocated
  metadata->file = file;
  metadata->line = line;
  metadata->next = g_active_list;
  g_active_list = metadata;

  // update active allocations
  g_nactive++;
  g_ntotal++;
  g_active_size += sz;
  g_total_size += sz;

  //update allocations for heavy hitter report
  int site_index = find_site_index(file, line);
  if (site_index != -1) {
    sites[site_index].allocated_bytes += sz;
    total_allocated_bytes += sz;
  }

  // update heap min and max
  if (!g_heap_min || (char *)payload < g_heap_min) {
    g_heap_min = (char *)payload;
  }
  if (!g_heap_max || (char *)payload + payloadSize > g_heap_max) {
    g_heap_max = (char *)payload + payloadSize;
  }

  return payload;
}

/// cs0019_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to cs0019_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void cs0019_free(void *ptr, const char *file, int line) {
  (void)file, (void)line; // avoid uninitialized variable warnings
  if (!ptr) return;

  // check if pointer is in heap bounds 
  if ((char *)ptr < g_heap_min || (char *)ptr > g_heap_max) {
    fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n",
                file, line, ptr);
    ABORT();
  }

  struct block_metadata *current = g_active_list;
  struct block_metadata *prev = NULL;

  while (current && current->ptr != ptr) {
    // check if pointer is inside an allocated block
    if ((char *)ptr > (char *)current->ptr && (char *)ptr < (char *)current->ptr + current->size) {
      size_t offset = (char *)ptr - (char *)current->ptr;
      fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n",
              file, line, ptr);
      fprintf(stderr, "  %s:%d: %p is %zu bytes inside a %zu byte region allocated here\n",
              current->file, current->line, ptr, offset, current->size);
    }

    prev = current;
    current = current->next;
  }

  if (!current) {
    fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p\n", file, line, ptr);
    ABORT();
  }

  // check for double free
  if (current->status == 0) {
    fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
    ABORT();
  }

  // check for wild write
  size_t sz = current->size;
  unsigned char *canary = (unsigned char *)ptr + sz;
  if (*canary != CANARY) {
    fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
    ABORT();
  }

  // mark as freed 
  current->status = 0;
  // update stats
  g_nactive--;
  g_active_size -= sz;

  // remove metadata from acrive linked list
  if (prev == NULL) {
    g_active_list = current->next;
  } else {
    prev->next = current->next;
  }

  // free payload, and metadata
  base_free(ptr);
  base_free(current);
}

/// cs0019_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `cs0019_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `cs0019_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

// update to locate metadata properly
void *cs0019_realloc(void *ptr, size_t sz, const char *file, int line) {

  void *new_ptr = NULL;
  if (sz) {
    new_ptr = cs0019_malloc(sz, file, line);
  }

  if (ptr && new_ptr) {
// Copy the data from `ptr` into `new_ptr`.
// To do that, we must figure out the size of allocation `ptr`.
// Your code here (to fix test014).
    struct block_metadata *metadata = g_active_list;
    while (metadata && metadata->ptr != ptr) {
      metadata = metadata->next;
    }
    if (metadata == NULL) {
      fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p\n", file, line, ptr);
      ABORT();
    }
    size_t old_size = metadata->size;


    // copy whichever is smaller
    if (old_size < sz) {
      memcpy(new_ptr, ptr, old_size);
    } else {
      memcpy(new_ptr, ptr, sz);
    }
  }
  cs0019_free(ptr, file, line);
  return new_ptr;
}

/// cs0019_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then cs0019_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void *cs0019_calloc(size_t nmemb, size_t sz, const char *file, int line) {
// Your code here (to fix test016).

  //check for multiplication overflow; nmemb!=0, and (SIZE_MAX / nmemb) < sz
  if (nmemb == 0 || (SIZE_MAX / nmemb) < sz) {
    g_nfail++;
    g_fail_size += nmemb * sz;
    return NULL;
  }

  // calculate total size of allocation
  size_t totalSize = nmemb * sz;
  void *ptr = cs0019_malloc(totalSize, file, line);
  if (ptr) {
    memset(ptr, 0, totalSize);
  }
  return ptr;
}

/// cs0019_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

// we set each byte in stats to 255, should be 0 -> change 255 to 0 
//we also don't track allocatiosn and failures; thefore we need to add this
// idea -> in malloc, update counter
// in free, use stored size info to update active counters
// in get stats, copy values from gloval counter into stats struct 
void cs0019_getstatistics(struct cs0019_statistics *stats) {
  // Stub: set all statistics to enormous numbers
  memset(stats, 0, sizeof(struct cs0019_statistics));

  stats->nactive = g_nactive;
  stats->ntotal = g_ntotal;
  stats->nfail = g_nfail;
  stats->active_size = g_active_size;
  stats->total_size = g_total_size;
  stats->fail_size = g_fail_size;
  stats->heap_min = g_heap_min;
  stats->heap_max = g_heap_max;
}

/// cs0019_printstatistics()
///    Print the current memory statistics.

void cs0019_printstatistics(void) {
  struct cs0019_statistics stats;
  cs0019_getstatistics(&stats);

  printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
         stats.nactive, stats.ntotal, stats.nfail);
  printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
         stats.active_size, stats.total_size, stats.fail_size);
}

/// cs0019_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void cs0019_printleakreport(void) {
    struct block_metadata *current = g_active_list;
    
    while (current) {
        printf("LEAK CHECK: %s:%d: allocated object %p with size %zu\n",
               current->file, current->line, current->ptr, current->size);
        current = current->next;
    }
}

/// cs0019_printheavyhitterreport()
///    Print a report of all the heavy hitters as described
///    in the coursework handout.


static int compare_sites(const void *a, const void *b) {
    const struct allocation_sites *site_a = (const struct allocation_sites *)a;
    const struct allocation_sites *site_b = (const struct allocation_sites *)b;
    
    if (site_b->allocated_bytes > site_a->allocated_bytes) return 1;
    if (site_b->allocated_bytes < site_a->allocated_bytes) return -1;
    return 0;
}

void cs0019_printheavyhitterreport(void) {
  //make copy of sites array
  struct allocation_sites sorted[MAX_SITES];
  memcpy(sorted, sites, sizeof(sites));
  //sort copy using compare_sites
  qsort(sorted, site_count, sizeof(struct allocation_sites), compare_sites);

  // list heavy hitters (20% or more of total allocations)
  for (int i = 0; i < site_count; i++) {
    if (sorted[i].allocated_bytes == 0){
      break;
    }
  
    double percentage = ((double)sorted[i].allocated_bytes / total_allocated_bytes) * 100;
    if (percentage >= 20.0) {
            printf("HEAVY HITTER: %s:%d: %zu bytes (~%.1f%%)\n",
                   sorted[i].file,
                   sorted[i].line,
                   sorted[i].allocated_bytes,
                   percentage);
    } else {
      break; // list is sorted so we've seen all heavy hitters
    }
  }

}

////////
  //FILE *debug = fopen("free_debug.log", "a");
 // fprintf(debug, "\n=== New free call ===\n");
  //fprintf(debug, "Freeing pointer: %p\n", ptr);
 // fprintf(debug, "Current heap_min: %p\n", g_heap_min);
 // fprintf(debug, "Current heap_max: %p\n", g_heap_max);
///%