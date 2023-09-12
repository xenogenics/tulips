#include "Context.h"
#include <fcntl.h>
#include <openssl/err.h>

namespace tulips::ssl {

/*
 * Utilities
 */

const SSL_METHOD*
getMethod(const Protocol type, const bool server, long& flags)
{
  const SSL_METHOD* method = nullptr;
  /*
   * Check requested type.
   */
  switch (type) {
    case Protocol::SSLv3: {
      method = server ? SSLv23_server_method() : SSLv23_client_method();
      flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
              SSL_OP_NO_TLSv1_2;
      break;
    }
    case Protocol::TLS: {
      method = server ? TLS_server_method() : TLS_client_method();
      flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
              SSL_OP_NO_TLSv1_1;
      break;
    }
  }
  /*
   * Return the SSL method.
   */
  return method;
}

std::string
errorToString(const int err)
{
  switch (err) {
    case SSL_ERROR_NONE:
      return "SSL_ERROR_NONE";
    case SSL_ERROR_ZERO_RETURN:
      return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_READ:
      return "SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_WRITE:
      return "SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_CONNECT:
      return "SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
      return "SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_X509_LOOKUP:
      return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
      return "SSL_ERROR_SYSCALL";
    case SSL_ERROR_SSL: {
      char buffer[1024];
      ERR_error_string_n(ERR_peek_error(), buffer, 1024);
      return { buffer };
    }
  }
  return "no error";
}

/*
 * SSL context.
 */

Context::Context(SSL_CTX* ctx, system::Logger& log, const size_t buflen,
                 const api::interface::Client::ID id, void* cookie,
                 const system::Clock::Value ts, const int keyfd)
  : log(log)
  , buflen(buflen)
  , id(id)
  , cookie(cookie)
  , ts(ts)
  , keyfd(keyfd)
  , bin(bio::allocate(buflen))
  , bout(bio::allocate(buflen))
  , ssl(SSL_new(ctx))
  , state(State::Closed)
  , blocked(false)
  , rdbf(new uint8_t[buflen])
{
  SSL_set_bio(ssl, bin, bout);
  SSL_set_app_data(ssl, this);
}

Context::~Context()
{
  /*
   * Close the key file.
   */
  if (keyfd != -1) {
    ::close(keyfd);
  }
  /*
   * Delete the read buffer.
   */
  delete[] rdbf;
  /*
   * No need to free the BIOs, SSL_free does that for us.
   */
  SSL_free(ssl);
}

Action
Context::abortOrClose(const Action r, const uint32_t alen, uint8_t* const sdata,
                      uint32_t& slen)
{
  /*
   * Process an abort request.
   */
  if (r == Action::Abort) {
    log.debug("SSL", "aborting connection");
    return Action::Abort;
  }
  /*
   * Process a close request.
   */
  if (r == Action::Close) {
    log.debug("SSL", "closing connection");
    /*
     * Call SSL_shutdown, repeat if necessary.
     */
    int ret = SSL_shutdown(ssl);
    if (ret == 0) {
      ret = SSL_shutdown(ssl);
    }
    /*
     * Check that the SSL connection expect an answer from the other peer.
     */
    if (ret < 0) {
      auto err = SSL_get_error(ssl, ret);
      if (err != SSL_ERROR_WANT_READ) {
        log.error("SSL", "SSL_shutdown error: ", ssl::errorToString(err));
        return Action::Abort;
      }
      /*
       * Flush the shutdown signal.
       */
      state = State::Shutdown;
      return flush(alen, sdata, slen);
    }
    log.error("SSL", "SSL_shutdown error, aborting connection");
    return Action::Abort;
  }
  /*
   * Default return.
   */
  return Action::Continue;
}

Action
Context::flush(uint32_t alen, uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Check and send any data in the BIO buffer.
   */
  size_t len = pending();
  if (len == 0) {
    return Action::Continue;
  }
  /*
   * Send the response.
   */
  size_t rlen = len > alen ? alen : len;
  BIO_read(bout, sdata, (int)rlen);
  slen = rlen;
  return Action::Continue;
}

void
Context::saveKeys(std::string_view prefix)
{
  auto spath = std::string(prefix) + "_" + std::to_string(id) + ".keys";
  keyfd = ::open(spath.c_str(), O_CREAT | O_RDWR);
}

}
