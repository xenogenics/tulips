#include "Context.h"
#include <tulips/ssl/Client.h>
#include <tulips/stack/Utils.h>
#include <stdexcept>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace tulips::ssl {

Client::Client(system::Logger& log, interface::Client::Delegate& delegate,
               transport::Device& device, [[maybe_unused]] const size_t nconn,
               const Protocol type)
  : m_delegate(delegate)
  , m_log(log)
  , m_dev(device)
  , m_client(std::make_unique<tulips::api::Client>(log, *this, device, nconn))
  , m_context(nullptr)
{
  m_log.debug("SSLCLI", "protocol: ", ssl::toString(type));
  /*
   * Initialize the SSL library.
   */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  /*
   * Create the SSL context.
   */
  long flags = 0;
  m_context = SSL_CTX_new(ssl::getMethod(type, false, flags));
  if (m_context == nullptr) {
    throw std::runtime_error("SSL_CTX_new failed");
  }
  SSL_CTX_set_options(AS_SSL(m_context), flags);
  /*
   * Use AES ciphers.
   */
  const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!PSK:!SRP:!MD5:!RC4:!3DES";
  int res = SSL_CTX_set_cipher_list(AS_SSL(m_context), PREFERRED_CIPHERS);
  if (res != 1) {
    throw std::runtime_error("SSL_CTX_set_cipher_list failed");
  }
}

Client::Client(system::Logger& log, interface::Client::Delegate& delegate,
               transport::Device& device, const size_t nconn,
               const Protocol type, std::string_view cert, std::string_view key)
  : Client(log, delegate, device, nconn, type)
{
  int err = 0;
  /*
   * Load certificate and private key files, and check consistency.
   */
  auto scert = std::string(cert);
  err = SSL_CTX_use_certificate_file(AS_SSL(m_context), scert.c_str(),
                                     SSL_FILETYPE_PEM);
  if (err != 1) {
    throw std::runtime_error("SSL_CTX_use_certificate_file failed");
  }
  m_log.info("SSLCLI", "using certificate: ", cert);
  /*
   * Indicate the key file to be used.
   */
  auto skey = std::string(key);
  err = SSL_CTX_use_PrivateKey_file(AS_SSL(m_context), skey.c_str(),
                                    SSL_FILETYPE_PEM);
  if (err != 1) {
    throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed");
  }
  m_log.info("SSLCLI", "using key: ", key);
  /*
   * Make sure the key and certificate file match.
   */
  if (SSL_CTX_check_private_key(AS_SSL(m_context)) != 1) {
    throw std::runtime_error("SSL_CTX_check_private_key failed");
  }
}

Client::~Client()
{
  SSL_CTX_free(AS_SSL(m_context));
}

Status
Client::open(ID& id)
{
  Status res = m_client->open(id);
  if (res != Status::Ok) {
    return res;
  }
  return Status::Ok;
}

Status
Client::connect(const ID id, stack::ipv4::Address const& ripaddr,
                const stack::tcpv4::Port rport)
{

  void* cookie = m_client->cookie(id);
  /*
   * If the cookie is nullptr, we are not connected yet.
   */
  if (cookie == nullptr) {
    Status res = m_client->connect(id, ripaddr, rport);
    if (res != Status::Ok) {
      return res;
    }
    cookie = m_client->cookie(id);
  }
  /*
   * Perform the handshake.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  switch (c.state) {
    /*
     * Perform the client SSL handshake.
     */
    case Context::State::Connect: {
      int e = SSL_connect(c.ssl);
      switch (e) {
        case 0: {
          m_log.error("SSLCLI", "connect error");
          return Status::ProtocolError;
        }
        case 1: {
          m_log.debug("SSLCLI", "SSL_connect successful");
          c.state = Context::State::Ready;
          return Status::Ok;
        }
        default: {
          if (SSL_get_error(c.ssl, e) != SSL_ERROR_WANT_READ) {
            auto error = ssl::errorToString(c.ssl, e);
            m_log.error("SSLCLI", "connect error: ", error);
            return Status::ProtocolError;
          }
          Status res = flush(id, cookie);
          if (res != Status::Ok) {
            return res;
          }
          return Status::OperationInProgress;
        }
      }
    }
    /*
     * Connection is ready.
     */
    case Context::State::Ready: {
      return Status::Ok;
    }
    /*
     * Connection is being shut down.
     */
    case Context::State::Shutdown: {
      return Status::InvalidArgument;
    }
    /*
     * Default.
     */
    default: {
      return Status::ProtocolError;
    }
  }
}

Status
Client::abort(const ID id)
{
  /*
   * Grab the context.
   */
  void* cookie = m_client->cookie(id);
  if (cookie == nullptr) {
    return Status::InvalidArgument;
  }
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Check if the connection is in the right state.
   */
  if (c.state != Context::State::Ready && c.state != Context::State::Shutdown) {
    return Status::NotConnected;
  }
  /*
   * Abort the connection.
   */
  return m_client->abort(id);
}

Status
Client::close(const ID id)
{
  /*
   * Grab the context.
   */
  void* cookie = m_client->cookie(id);
  if (cookie == nullptr) {
    return Status::NotConnected;
  }
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Check if the connection is in the right state.
   */
  if (c.state != Context::State::Ready && c.state != Context::State::Shutdown) {
    return Status::NotConnected;
  }
  if (c.state == Context::State::Shutdown) {
    return Status::OperationInProgress;
  }
  /*
   * Mark the state as shut down.
   */
  c.state = Context::State::Shutdown;
  /*
   * Call SSL_shutdown, repeat if necessary.
   */
  int e = SSL_shutdown(c.ssl);
  /*
   * Go through the shutdown state machine.
   */
  switch (e) {
    case 0: {
      m_log.debug("SSLCLI", "SSL shutdown sent");
      flush(id, cookie);
      return Status::OperationInProgress;
    }
    case 1: {
      m_log.debug("SSLCLI", "shutdown completed");
      return m_client->close(id);
    }
    default: {
      auto error = ssl::errorToString(c.ssl, e);
      m_log.error("SSLCLI", "SSL_shutdown error: ", error);
      return Status::ProtocolError;
    }
  }
}

bool
Client::isClosed(const ID id) const
{
  return m_client->isClosed(id);
}

Status
Client::send(const ID id, const uint32_t len, const uint8_t* const data,
             uint32_t& off)
{
  /*
   * Grab the context.
   */
  void* cookie = m_client->cookie(id);
  if (cookie == nullptr) {
    return Status::InvalidArgument;
  }
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Check if the connection is in the right state.
   */
  if (c.state != Context::State::Ready) {
    return Status::InvalidConnection;
  }
  /*
   * Check if we can write anything.
   */
  if (c.blocked) {
    return Status::OperationInProgress;
  }
  /*
   * Write the data. With BIO mem, the write will always succeed.
   */
  off = 0;
  off += SSL_write(c.ssl, data, (int)len);
  /*
   * Flush the data.
   */
  return flush(id, cookie);
}

system::Clock::Value
Client::averageLatency(const ID id)
{
  return m_client->averageLatency(id);
}

void*
Client::onConnected(ID const& id, void* const cookie, uint8_t& opts)
{
  void* user = m_delegate.onConnected(id, cookie, opts);
  auto* c = new Context(AS_SSL(m_context), m_log, m_dev.mss(), user);
  c->state = Context::State::Connect;
  return c;
}

Action
Client::onAcked(ID const& id, void* const cookie)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Return if the handshake was not done.
   */
  if (c.state != Context::State::Ready) {
    return Action::Continue;
  }
  /*
   * Notify the delegate.
   */
  return m_delegate.onAcked(id, c.cookie);
}

Action
Client::onAcked(ID const& id, void* const cookie, const uint32_t alen,
                uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * If the BIO has data pending, flush it.
   */
  return c.onAcked(id, m_delegate, alen, sdata, slen);
}

Action
Client::onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                  const uint32_t len)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Decrypt the incoming data.
   */
  return c.onNewData(id, m_delegate, data, len);
}

Action
Client::onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                  const uint32_t len, const uint32_t alen, uint8_t* const sdata,
                  uint32_t& slen)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Write the data in the input BIO.
   */
  return c.onNewData(id, m_delegate, data, len, alen, sdata, slen);
}

void
Client::onClosed(ID const& id, void* const cookie)
{
  auto* c = reinterpret_cast<Context*>(cookie);
  if (c != nullptr) {
    m_delegate.onClosed(id, c->cookie);
    delete c;
  }
}

Status
Client::flush(const ID id, void* const cookie)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Send the pending data.
   */
  size_t len = c.pending();
  if (len == 0) {
    return Status::Ok;
  }
  uint32_t rem = 0;
  Status res = m_client->send(id, len, ssl::bio::readAt(c.bout), rem);
  if (res != Status::Ok) {
    c.blocked = res == Status::OperationInProgress;
    return res;
  }
  ssl::bio::skip(c.bout, rem);
  return Status::Ok;
}

}
