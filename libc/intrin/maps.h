#ifndef COSMOPOLITAN_MAPS_H_
#define COSMOPOLITAN_MAPS_H_
#include "libc/intrin/atomic.h"
#include "libc/intrin/dll.h"
#include "libc/intrin/tree.h"
#include "libc/runtime/runtime.h"
#include "libc/thread/tls2.internal.h"
COSMOPOLITAN_C_START_

#define MAP_TREE_CONTAINER(e) TREE_CONTAINER(struct Map, tree, e)
#define MAP_FREE_CONTAINER(e) DLL_CONTAINER(struct Map, free, e)

struct Map {
  char *addr;        /* granule aligned */
  size_t size;       /* must be nonzero */
  int64_t off;       /* ignore for anon */
  int prot;          /* memory protects */
  int flags;         /* memory map flag */
  bool iscow;        /* windows nt only */
  bool readonlyfile; /* windows nt only */
  unsigned visited;  /* checks and fork */
  intptr_t hand;     /* windows nt only */
  union {
    struct Tree tree;
    struct Dll free;
  };
};

struct Maps {
  atomic_int lock;
  struct Tree *maps;
  struct Dll *free;
  size_t count;
  size_t pages;
  atomic_size_t rollo;
  struct Map stack;
  struct Map guard;
};

struct AddrSize {
  char *addr;
  size_t size;
};

extern struct Maps __maps;

void *randaddr(void);
void __maps_init(void);
bool __maps_lock(void);
void __maps_check(void);
void __maps_unlock(void);
void __maps_add(struct Map *);
void __maps_free(struct Map *);
struct Map *__maps_alloc(void);
struct Map *__maps_ceil(const char *);
struct Map *__maps_floor(const char *);
void __maps_stack(char *, int, int, size_t, int, intptr_t);
int __maps_compare(const struct Tree *, const struct Tree *);
struct AddrSize __get_main_stack(void);

forceinline optimizespeed int __maps_search(const void *key,
                                            const struct Tree *node) {
  const char *addr = (const char *)key;
  const struct Map *map = (const struct Map *)MAP_TREE_CONTAINER(node);
  return (addr > map->addr) - (addr < map->addr);
}

static struct Map *__maps_next(struct Map *map) {
  struct Tree *node;
  if ((node = tree_next(&map->tree)))
    return MAP_TREE_CONTAINER(node);
  return 0;
}

static struct Map *__maps_first(void) {
  struct Tree *node;
  if ((node = tree_first(__maps.maps)))
    return MAP_TREE_CONTAINER(node);
  return 0;
}

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_MAPS_H_ */
