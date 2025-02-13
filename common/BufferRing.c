#include "BufferRing.h"

void buffer_ring_init(BufferRing *b) {
	atomic_init(&b->head, 0);
	atomic_init(&b->tail, 0);
}

void buffer_ring_push(BufferRing *b, uint8_t value) {
	int tail = atomic_load(&b->tail);
	int next = (tail + 1) % BUFFER_SIZE;

	if (next == atomic_load(&b->head)) {
		return;
	}

	b->buffer[tail] = value;
	atomic_store(&b->tail, next);
}

uint8_t buffer_ring_pop(BufferRing *b) {
	int head = atomic_load(&b->head);
	if (head == atomic_load(&b->tail)) {
		return -1;
	}
	int value = b->buffer[head];
	atomic_store(&b->head, (head + 1) % BUFFER_SIZE);
	return value;
}

int buffer_ring_skip(BufferRing *b,int n) {
	int head = atomic_load(&b->head);
	int tail = atomic_load(&b->tail);
	int available = (tail >= head) ? (tail - head) : (BUFFER_SIZE - head + tail);

	if (n > available) {
		atomic_store(&b->head, tail);  // Очередь пуста
		return available;
	}
	else {
		atomic_store(&b->head, (head + n) % BUFFER_SIZE);
		return n;
	}
}

int buffer_ring_is_empty(BufferRing *b) {
	int head = atomic_load(&b->head);
	if (head == atomic_load(&b->tail)) {
		return 1;
	}
	return 0;
}

int buffer_ring_clear(BufferRing *b) {
	atomic_store(&b->head,0);
	atomic_store(&b->tail,0);
}

int buffer_ring_available(BufferRing *b) {
	int head = atomic_load(&b->head);
	int tail = atomic_load(&b->tail);
	return (tail >= head) ? (tail - head) : (BUFFER_SIZE - head + tail);
}

bool read_bytes(void *data, size_t sz,BufferRing *b) {
	size_t n = 0;
	while(!buffer_ring_is_empty(b) && n < sz) {
		((uint8_t *)data)[n++] = buffer_ring_pop(b);
	}
	return n == sz;
}

size_t write_bytes(const void *data, size_t sz,BufferRing *b) {
	size_t i;
	for(i = 0; i < sz; i++) {
		buffer_ring_push(b,((uint8_t *)data)[i]);
	}
	return sz;
}

static bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t limit) {
	return read_bytes(data, limit, (BufferRing *)ctx->buf);
}

static size_t buffer_writer(cmp_ctx_t *ctx, const void *data, size_t count) {
	return write_bytes(data, count, (BufferRing *)ctx->buf);
}

static bool buffer_skipper(cmp_ctx_t *ctx, size_t count) {
	return buffer_ring_skip((BufferRing *)ctx->buf, count) == count;
}

void cmp_init_buffer_ring(cmp_ctx_t *cmp,BufferRing *b) {
	cmp_init(cmp, b, buffer_reader, buffer_skipper, buffer_writer);
}
