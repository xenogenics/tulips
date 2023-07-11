/*
 * Copyright (c) 2020, International Business Machines
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "BIO.h"
#include <openssl/bio.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Compiler.h>

namespace tulips { namespace ssl { namespace bio {

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
  auto* b = reinterpret_cast<system::CircularBuffer*>(BIO_get_data(h));
  if (b == nullptr) {
    return 0;
  }
  if (BIO_get_shutdown(h) && BIO_get_init(h)) {
    delete b;
    BIO_set_data(h, nullptr);
  }
  return 1;
}

BIO*
allocate(const size_t size)
{
  /*
   * NOTE(xrg): this will leak.
   *
   * Before OpenSSL v3, this was declared as a statically allocated variable.
   * Since OpenSSL v3, there is no proper way to deallocate a BIO_METHOD.
   */
  static BIO_METHOD* method = nullptr;
  /*
   * Allocate the BIO method.
   */
  if (method == nullptr) {
    auto index = BIO_get_new_index();
    method = BIO_meth_new(index, "circular memory buffer");
  }
  /*
   * Populate the method.
   */
  BIO_meth_set_write(method, s_write);
  BIO_meth_set_read(method, s_read);
  BIO_meth_set_ctrl(method, s_ctrl);
  BIO_meth_set_create(method, s_create);
  BIO_meth_set_destroy(method, s_destroy);
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

}}}
