// SO - Projekt 1
// Oskar Tołkacz, 291583

#include "malloc.h"
#include <stdio.h>
#include <sys/queue.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
// DEFINES DEFINES DEFINES DEFINES DEFINES DEFINES DEFINES DEFINES DEFINES DEFIN
// -----------------------------------------------------------------------------

#define PAGE_SIZE (getpagesize())
#define MIN_BLOCK_SIZE (2 * sizeof(void *))
#define MIN_ARENA_SIZE 524288 // 512 * 1024
#define CANARY_CONST 0xd0dad0dad0dad0da

#define abs(x) ((x) >= 0 ? (x) : -(x))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

typedef struct mem_block mem_block_t;
typedef struct mem_arena mem_arena_t;
typedef LIST_ENTRY(mem_block) mb_node_t;
typedef LIST_ENTRY(mem_arena) ma_node_t;
typedef LIST_HEAD(, mem_block) mb_list_t;
typedef LIST_HEAD(, mem_arena) ma_list_t;

// -----------------------------------------------------------------------------
// STRUCTURES STRUCTURES STRUCTURES STRUCTURES STRUCTURES STRUCTURES STRUCTURES
// -----------------------------------------------------------------------------

struct mem_block
{
  uint64_t canary;
  int64_t mb_size; /* mb_size > 0 => free, mb_size < 0 => allocated */
  union
  {
    mb_node_t mb_link;   /* link on free block list, valid if block is free */
    uint64_t mb_data[0]; /* user data pointer, valid if block is allocated */
  };
};

struct mem_arena
{
  ma_node_t ma_link;     /* link on list of all arenas */
  mb_list_t ma_freeblks; /* list of all free blocks in the arena */
  int64_t size;          /* arena size minus sizeof(mem_arena_t) */
  mem_block_t ma_first;  /* first block in the arena */
};

static ma_list_t *arenas __used = &(ma_list_t){}; /* list of all arenas */
pthread_mutex_t mtx_lock;
pthread_mutex_t mtx_lock_debug;

// -----------------------------------------------------------------------------
// INIT INIT INIT INIT INIT INIT INIT INIT INIT INIT INIT INIT INIT INIT INIT IN
// -----------------------------------------------------------------------------

__constructor void __malloc_init(void)
{
  __malloc_debug_init();
  debug("Welcome to this custom malloc implementation! Hope it won't crash!");

  LIST_INIT(arenas);
  pthread_mutex_init(&mtx_lock, NULL);
  pthread_mutex_init(&mtx_lock_debug, NULL);
}

// -----------------------------------------------------------------------------
// DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
// -----------------------------------------------------------------------------

void mem_dump()
{
  //return;

  pthread_mutex_lock(&mtx_lock_debug);

  debug(" ");
  debug("MEM DUMP! ONLY FREE BLOCKS");

  mem_arena_t *current_arena;
  LIST_FOREACH(current_arena, arenas, ma_link)
  {
    debug("ARENA %p", (void *) current_arena);
    debug("size: %lu", current_arena->size);
    mem_block_t *current_block;
    LIST_FOREACH(current_block, &(current_arena->ma_freeblks), mb_link)
    {
      debug("    %p | size: %ld", (void *)current_block, current_block->mb_size);
    }
  }

  debug(" ");
  debug("-----------------------");

  pthread_mutex_unlock(&mtx_lock_debug);
}

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS HELPER FUNCTIONS HELPER FUNCTIONS HELPER FUNCTIONS HELPER FU
// -----------------------------------------------------------------------------

inline void check_block_consistency(mem_block_t *block)
{
  if (block->canary != CANARY_CONST)
  {
    debug("Unknown error occured, canary damaged!");
    exit(1);
  }
}

inline mem_block_t *get_prev_block(mem_block_t *block)
{
  return (mem_block_t *)((char *)block - abs(*(((int64_t *) block) - 1)) - sizeof(int64_t))-1;
}

inline mem_block_t *get_next_block(mem_block_t *block)
{
  return (mem_block_t *)((char *)(block+1) - 1 + abs(block->mb_size) + 2*sizeof(void *));
}

size_t get_aligned_size(size_t alignment, size_t size)
{
  return ((size + alignment - 1) / alignment) * alignment;
}

int64_t *get_boundary_tag_address(mem_block_t *block)
{
  // block meta data           - ptr returned to usr  - boundary tag
  // sizeof(mem_block_t) bytes - block->mb_size bytes - sizeof(int64_t) bytes
  return (int64_t *)((char *)(block + 1) + abs(block->mb_size));
}

// boundary tag allows to traverse the list backwards by keeping the size
// of the previous block on the end of that block
void set_boundary_tag(mem_block_t *block)
{
  *get_boundary_tag_address(block) = block->mb_size;
}

mem_arena_t *get_new_arena_raw(size_t size)
{
  return mmap(
    NULL,
    size,
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0);
}

mem_block_t *find_free_block_in_arena(size_t size, mem_arena_t *arena)
{
  mem_block_t *current_block;
  LIST_FOREACH(current_block, &(arena->ma_freeblks), mb_link)
  {
    check_block_consistency(current_block);
    if ((size_t)current_block->mb_size >= size)
      return current_block;
  }
  return NULL;
}

mem_block_t *find_free_block(size_t size)
{
  mem_arena_t *current_arena;
  LIST_FOREACH(current_arena, arenas, ma_link)
  {
    mem_block_t *current_block = find_free_block_in_arena(size, current_arena);
    if (current_block != NULL)
      return current_block;
  }
  return NULL;
}

void create_free_block(size_t size, mem_block_t *block)
{
  block->canary = CANARY_CONST;
  block->mb_size = size;
  set_boundary_tag(block);
}

size_t new_arena_size(size_t size)
{
  return sizeof(mem_arena_t) + size + sizeof(int64_t);
}

mem_arena_t *create_new_arena(size_t size)
{
  size = max(size, MIN_ARENA_SIZE);
  mem_arena_t *new_arena = get_new_arena_raw(new_arena_size(size));

  if (new_arena == NULL) return NULL;

  LIST_INSERT_HEAD(arenas, new_arena, ma_link);

  LIST_INIT(&(new_arena->ma_freeblks));
  new_arena->size = size;
  create_free_block(size, &(new_arena->ma_first));
  LIST_INSERT_HEAD(&(new_arena->ma_freeblks), &(new_arena->ma_first), mb_link);

  return new_arena;
}

// assumes that block is free and its size is big enough and it's aligned
void allocate_block(size_t size, mem_block_t *block)
{
  check_block_consistency(block);

  size_t potential_leftover_block_size = 0;
  if (block->mb_size - size > sizeof(mem_block_t) + sizeof(int64_t))
    potential_leftover_block_size =
      block->mb_size - size - sizeof(mem_block_t) - sizeof(int64_t);

  if (potential_leftover_block_size >= MIN_BLOCK_SIZE)
  {
    block->mb_size = -size;

    set_boundary_tag(block);

    mem_block_t *leftover_block =
      (mem_block_t *)(get_boundary_tag_address(block) + 1);

    create_free_block(potential_leftover_block_size, leftover_block);
    LIST_INSERT_AFTER(block, leftover_block, mb_link);
    LIST_REMOVE(block, mb_link);
  }
  else
  {
    LIST_REMOVE(block, mb_link);
    block->mb_size *= -1;
  }
}

// assumes that block is allocated
void *get_user_pointer(size_t alignment, mem_block_t *block)
{
  check_block_consistency(block);
  void *return_ptr = (void *) get_aligned_size(alignment, (size_t) block->mb_data);

  // these 0's can be used to find block meta data easily
  memset(&block->mb_data, 0, return_ptr-(void *)&block->mb_data);

  return return_ptr;
}

int alignment_incorrect(size_t alignment)
{
  return (alignment & (alignment - 1)) || alignment % sizeof(void *) != 0;
}

mem_block_t *get_ptr_block(void *ptr)
{
    int64_t *potential_block = (int64_t *) ptr - 1;

    while (*potential_block == 0)
      potential_block--;

    potential_block = (int64_t *)potential_block-1;

    check_block_consistency((mem_block_t *) potential_block);
    return (mem_block_t *)potential_block;
}

mem_arena_t *get_block_arena(mem_block_t *block)
{
  if (block == NULL) return NULL;

  mem_arena_t *current_arena;
  LIST_FOREACH(current_arena, arenas, ma_link)
  {
    if ((char *)current_arena < (char *)block &&
        (char *)block < (char *)current_arena + sizeof(mem_arena_t) + current_arena->size)
      return current_arena;
  }
  return NULL;
}

mem_block_t *merge_blocks_raw(mem_block_t *left_block, mem_block_t *right_block)
{
  create_free_block(
    left_block->mb_size + sizeof(int64_t) + sizeof(mem_block_t) + right_block->mb_size,
    left_block);

  return left_block;
}

mem_block_t *merge_blocks(mem_block_t *left_block, mem_block_t *right_block)
{
  if (left_block == NULL) return right_block;
  if (right_block == NULL) return left_block;
  if (left_block->mb_size < 0) return right_block;
  if (right_block->mb_size < 0) return left_block;

  return merge_blocks_raw(left_block, right_block);
}

void add_free_block_to_list(mem_block_t *block, mem_arena_t *arena)
{
  check_block_consistency(block);

  mem_block_t *current_block = block;
  mem_block_t *last_block;

  LIST_FOREACH(current_block, &(arena->ma_freeblks), mb_link)
  {
      if (current_block > block)
      {
          LIST_INSERT_BEFORE(current_block, block, mb_link);
          return;
      }
      last_block  = current_block;
  }

  LIST_INSERT_AFTER(last_block, block, mb_link);
}

// -----------------------------------------------------------------------------
// IMPLEMENTATION IMPLEMENTATION IMPLEMENTATION IMPLEMENTATION IMPLEMENTATION IM
// -----------------------------------------------------------------------------

void __my_free(void *ptr)
{
  debug("%s(%p)", __func__, ptr);

  if (ptr == NULL) return;

  pthread_mutex_lock(&mtx_lock);

  mem_block_t *block = get_ptr_block(ptr);
  block->mb_size *= -1;

  mem_arena_t *arena = get_block_arena(block);

  mem_block_t *prev_block = get_prev_block(block);
  if (prev_block < &(arena->ma_first))
    prev_block = NULL;

  mem_block_t *next_block = get_next_block(block);
  if ((char *)next_block > (char *)(arena+1)+sizeof(arena->size)+sizeof(int64_t))
    next_block = NULL;

  if ((prev_block == NULL || prev_block->mb_size < 0)
      &&
      (next_block == NULL || next_block->mb_size < 0))
  {
    add_free_block_to_list(block, arena);
  }
  else
  {
    merge_blocks(block, next_block);
    merge_blocks(prev_block, block);
  }

  if (arena->size == arena->ma_first.mb_size)
  {
    LIST_REMOVE(arena, ma_link);
    size_t munmap_size = sizeof(mem_arena_t) + arena->size + sizeof(int64_t);
    int munmap_status = munmap((void *)arena, munmap_size);
    assert(munmap_status == 0);
  }

  pthread_mutex_unlock(&mtx_lock);
}

void *__my_memalign(size_t alignment, size_t size)
{
  debug("%s(%ld, %ld)", __func__, alignment, size);

  if (size > INT64_MAX) { errno = ENOMEM; return NULL; }
  if (alignment_incorrect(alignment)) { errno = EINVAL; return NULL; }
  if (size == 0) size = 1;

  size_t size_aligned = get_aligned_size(alignment, size);

  pthread_mutex_lock(&mtx_lock);

  mem_block_t *new_block = find_free_block(size_aligned);

  if (new_block == NULL)
  {
    mem_arena_t *new_arena = create_new_arena(size_aligned);
    new_block = find_free_block_in_arena(size_aligned, new_arena);
  }

  if (new_block == NULL)
  {
    pthread_mutex_unlock(&mtx_lock);
    return NULL;
  }

  allocate_block(size_aligned, new_block);
  void *user_ptr = get_user_pointer(alignment, new_block);

  pthread_mutex_unlock(&mtx_lock);
  return user_ptr;
}

size_t __my_malloc_usable_size(void *ptr)
{
  debug("%s(%p)", __func__, ptr);

  if (ptr == NULL) return 0;

  pthread_mutex_lock(&mtx_lock);
  mem_block_t *block = get_ptr_block(ptr);
  pthread_mutex_unlock(&mtx_lock);

  if (block == NULL) return 0;

  return abs(block->mb_size);
}

void *__my_malloc(size_t size)
{
  debug(" ");
  debug("%s(%ld)", __func__, size);

  if (size == 0) return NULL;
  void *ptr = __my_memalign(sizeof(void *), size);

  return ptr;
}

void *copy_realloc(void *ptr, size_t size)
{
  char *new_ptr = __my_malloc(size);
  if(new_ptr) memcpy(new_ptr, (char *)ptr, size);
  __my_free(ptr);

  return new_ptr;
}

void *__my_realloc(void *ptr, size_t size)
{
  debug("%s(%p, %ld)", __func__, ptr, size);

  mem_dump();

  if (ptr == NULL && size == 0) return __my_malloc(size);

  if (size > INT64_MAX)
  {
    errno = ENOMEM;
    return NULL;
  }

  if (ptr == NULL) return __my_malloc(size);

  if (size == 0)
  {
    __my_free(ptr);
    return NULL;
  }

  mem_block_t *block = get_ptr_block(ptr);

  debug("current size: %ld", block->mb_size);

  if ((uint64_t)abs(block->mb_size) >= size)
  {
    return ptr;
    //return copy_realloc(ptr, size);
    if (abs(block->mb_size) - size >= sizeof(mem_block_t) + MIN_BLOCK_SIZE + sizeof(int64_t))
    {
      create_free_block(-size, block);
      mem_block_t *next_block = get_next_block(block);
      create_free_block(
        abs(block->mb_size) - size - sizeof(mem_block_t) - sizeof(int64_t),
        next_block);
      add_free_block_to_list(next_block, get_block_arena(next_block));
    }
  }
  else
  {
    return copy_realloc(ptr, size);
    mem_block_t *next_block = get_next_block(block);

    if (next_block->mb_size > 0
        &&
        abs(block->mb_size) + next_block->mb_size + sizeof(mem_block_t) + sizeof(int64_t) >= size)
    {
      merge_blocks_raw(block, next_block);
      LIST_REMOVE(next_block, mb_link);

      mem_arena_t *arena = get_block_arena(block);
      if (arena->size == arena->ma_first.mb_size)
      {
        LIST_REMOVE(arena, ma_link);
        size_t munmap_size = sizeof(mem_arena_t) + arena->size + sizeof(int64_t);
        int munmap_status = munmap((void *)arena, munmap_size);
        assert(munmap_status == 0);
      }
    }
    else
    {
      return copy_realloc(ptr, size);
    }
  }

  return ptr;
}

// -----------------------------------------------------------------------------
// ALIASES ALIASES ALIASES ALIASES ALIASES ALIASES ALIASES ALIASES ALIASES ALIAS
// -----------------------------------------------------------------------------

/* DO NOT remove following lines */
__strong_alias(__my_free, cfree);
__strong_alias(__my_free, free);
__strong_alias(__my_malloc, malloc);
__strong_alias(__my_malloc_usable_size, malloc_usable_size);
__strong_alias(__my_memalign, aligned_alloc);
__strong_alias(__my_memalign, memalign);
__strong_alias(__my_realloc, realloc);
