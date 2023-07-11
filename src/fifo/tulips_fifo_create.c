#include <tulips/fifo/fifo.h>
#ifdef __linux__
#include <malloc.h>
#endif
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

tulips_fifo_error_t
tulips_fifo_create(const size_t depth, const size_t dlen,
                   tulips_fifo_t* const res)
{
  if (depth == 0) {
    return TULIPS_FIFO_INVALID_DEPTH;
  }
  if (dlen == 0) {
    return TULIPS_FIFO_INVALID_DATA_LEN;
  }
  if (*res != NULL) {
    return TULIPS_FIFO_ALREADY_ALLOCATED;
  }
  size_t payload = depth * dlen + sizeof(struct __tulips_fifo);
  void* data = malloc(payload);
  if (data == NULL) {
    return TULIPS_FIFO_MALLOC_FAILED;
  }
  memset(data, 0, payload);
  *res = (tulips_fifo_t)data;
  (*res)->depth = depth;
  (*res)->data_len = dlen;
  return TULIPS_FIFO_OK;
}
