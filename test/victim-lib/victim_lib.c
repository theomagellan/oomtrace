#include <stdlib.h>
#include <string.h>

static void **store = NULL;
static int n = 0;

void allocate_megabytes(int mb) {
    store = realloc(store, (size_t)(n + 1) * sizeof(void *));
    store[n] = malloc((size_t)mb * 1024 * 1024);
    memset(store[n], 0, (size_t)mb * 1024 * 1024);
    n++;
}
