#pragma once

#include <openssl/bio.h>

namespace tulips::ssl::bio {

BIO* allocate(const size_t size);

const uint8_t* readAt(BIO* h);
void skip(BIO* h, const size_t len);

}
