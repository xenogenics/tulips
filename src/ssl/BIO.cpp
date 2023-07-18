#include "BIO.h"
#include <openssl/bio.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Compiler.h>

namespace tulips::ssl::bio {

static const CircularBufferMethod CB_METHOD;

/*
 * Circular buffer BIO method.
 */

static int
s_write(BIO* h, const char* buf, int size)
{
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  BIO_clear_retry_flags(h);
  if (b->full()) {
    BIO_set_retry_read(h);
    return -1;
  }
  size_t res = b->write((const uint8_t*)buf, size);
  return (int)res;
}

static int
s_read(BIO* h, char* buf, int size)
{
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  BIO_clear_retry_flags(h);
  if (b->empty()) {
    BIO_set_retry_read(h);
    return -1;
  }
  size_t res = b->read((uint8_t*)buf, size);
  return (int)res;
}

static long
s_ctrl(BIO* h, int cmd, long num, UNUSED void* ptr)
{
  long ret = 1;
  /*
   * Grab the buffer.
   */
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  if (b == nullptr) {
    return 0;
  }
  /*
   * Check the command.
   */
  switch (cmd) {
    case BIO_CTRL_RESET:
      b->reset();
      break;
    case BIO_CTRL_EOF:
      ret = (long)b->empty();
      break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
      BIO_set_fd(h, (int)num, 0);
      break;
    case BIO_CTRL_INFO:
    case BIO_C_SET_BUF_MEM:
    case BIO_C_GET_BUF_MEM_PTR:
      ret = 0;
      break;
    case BIO_CTRL_GET_CLOSE:
      ret = (long)BIO_get_shutdown(h);
      break;
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(h, (int)num);
      break;
    case BIO_CTRL_WPENDING:
      ret = 0L;
      break;
    case BIO_CTRL_PENDING:
      ret = (long)b->available();
      break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      ret = 1;
      break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
      ret = 0;
      break;
  }
  return ret;
}

static int
s_create(BIO* h)
{
  BIO_set_shutdown(h, 0);
  BIO_set_init(h, 1);
  BIO_set_fd(h, -1, 0);
  BIO_set_data(h, nullptr);
  return 1;
}

static int
s_destroy(BIO* h)
{
  /*
   * Get the internal circular buffer.
   */
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  if (b == nullptr) {
    return 0;
  }
  /*
   * Delete the buffer and erase the internal data field.
   */
  delete b;
  BIO_set_data(h, nullptr);
  /*
   * Done.
   */
  return 1;
}

CircularBufferMethod::CircularBufferMethod()
{
  /*
   * Allocate the method.
   */
  auto index = BIO_get_new_index();
  m_method = BIO_meth_new(index, "circular memory buffer");
  /*
   * Populate the method.
   */
  BIO_meth_set_write(m_method, s_write);
  BIO_meth_set_read(m_method, s_read);
  BIO_meth_set_ctrl(m_method, s_ctrl);
  BIO_meth_set_create(m_method, s_create);
  BIO_meth_set_destroy(m_method, s_destroy);
}

/*
 * Helpers.
 */

BIO*
allocate(const size_t size)
{
  auto* method = CB_METHOD.method();
  /*
   * Allocate a BIO.
   */
  BIO* ret = BIO_new(method);
  if (ret == nullptr) {
    return nullptr;
  }
  /*
   * Allocate a circular buffer.
   */
  auto* b = new system::CircularBuffer(size);
  BIO_set_data(ret, (void*)b);
  BIO_set_flags(ret, 0);
  return ret;
}

const uint8_t*
readAt(BIO* h)
{
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  return b->readAt();
}

void
skip(BIO* h, const size_t len)
{
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  return b->skip(len);
}

}
