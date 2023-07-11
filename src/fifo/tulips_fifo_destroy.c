#include <tulips/fifo/fifo.h>
#ifdef __linux__
#include <malloc.h>
#endif
#include <stddef.h>
#include <stdlib.h>

tulips_fifo_error_t
tulips_fifo_destroy(tulips_fifo_t* const fifo)
{
  if (*fifo == NULL) {
    return TULIPS_FIFO_IS_NULL;
  }
  free(*fifo);
  *fifo = TULIPS_FIFO_DEFAULT_VALUE;
  return TULIPS_FIFO_OK;
}
