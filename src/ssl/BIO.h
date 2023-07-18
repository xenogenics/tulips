#pragma once

#include <openssl/bio.h>

namespace tulips::ssl::bio {

class CircularBufferMethod
{
public:
  CircularBufferMethod();

  ~CircularBufferMethod()
  {
    BIO_meth_free(m_method);
    m_method = nullptr;
  }

  inline BIO_METHOD* method() const { return m_method; }

private:
  BIO_METHOD* m_method;
};

BIO* allocate(const size_t size);

const uint8_t* readAt(BIO* h);
void skip(BIO* h, const size_t len);

}
