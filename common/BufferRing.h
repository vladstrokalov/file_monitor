#ifndef BUFFERRING_H
#define BUFFERRING_H
#include <stdatomic.h>
#include "cmp.h"

#define BUFFER_SIZE 8102

typedef struct {
	int buffer[BUFFER_SIZE];
	atomic_int head, tail;
} BufferRing;

extern void cmp_init_buffer_ring(cmp_ctx_t *cmp,BufferRing *b);
extern bool read_bytes(void *data, size_t sz,BufferRing *b);
extern size_t write_bytes(const void *data, size_t sz,BufferRing *b);
extern int buffer_ring_available(BufferRing *b);
extern int buffer_ring_clear(BufferRing *b);
extern int buffer_ring_is_empty(BufferRing *b);
#endif
