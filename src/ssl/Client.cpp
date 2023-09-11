#include "Context.h"
#include "tulips/stack/IPv4.h"
#include <tulips/ssl/Client.h>
#include <tulips/stack/Utils.h>
#include <cstdint>
#include <stdexcept>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/types.h>

namespace {

void
keylogCallback(const SSL* ssl, const char* line)
{
  void* appdata = SSL_get_app_data(ssl);
  auto* context = reinterpret_cast<tulips::ssl::Context*>(appdata);
  if (context->keyfd != -1) {
    ::write(context->keyfd, line, strlen(line));
    ::write(context->keyfd, "\n", 1);
  }
}

}

namespace tulips::ssl {

Client::Client(system::Logger& log, api::interface::Client::Delegate& delegate,
               transport::Device& device, const Protocol type,
               const size_t nconn, const bool save_keys)
  : m_delegate(delegate)
  , m_log(log)
  , m_dev(device)
  , m_client(std::make_unique<api::Client>(log, *this, device, nconn))
  , m_context(nullptr)
  , m_savekeys(save_keys)
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
  SSL_CTX_set_keylog_callback(AS_SSL(m_context), keylogCallback);
  /*
   * Use AES ciphers.
   */
  const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!PSK:!SRP:!MD5:!RC4:!3DES";
  int res = SSL_CTX_set_cipher_list(AS_SSL(m_context), PREFERRED_CIPHERS);
  if (res != 1) {
    throw std::runtime_error("SSL_CTX_set_cipher_list failed");
  }
}

Client::Client(system::Logger& log, api::interface::Client::Delegate& delegate,
               transport::Device& device, const Protocol type,
               std::string_view cert, std::string_view key, const size_t nconn)
  : Client(log, delegate, device, type, nconn, true)
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
Client::open(const uint8_t options, ID& id)
{
  Status res = m_client->open(options, id);
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
      int ret = SSL_connect(c.ssl);
      switch (ret) {
        case 0: {
          m_log.error("SSLCLI", "connect error");
          return Status::ProtocolError;
        }
        case 1: {
          m_log.debug("SSLCLI", "SSL_connect successful");
          c.cookie = m_delegate.onConnected(c.id, c.cookie);
          c.state = Context::State::Ready;
          return Status::Ok;
        }
        default: {
          auto err = SSL_get_error(c.ssl, ret);
          if (err != SSL_ERROR_WANT_READ) {
            auto error = ssl::errorToString(err);
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
  int ret = SSL_shutdown(c.ssl);
  /*
   * Go through the shutdown state machine.
   */
  switch (ret) {
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
      auto err = SSL_get_error(c.ssl, ret);
      auto error = ssl::errorToString(err);
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
   * Skip if the length is 0.
   */
  if (len == 0) {
    return Status::InvalidArgument;
  }
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
   * Write the data.
   */
  auto ret = SSL_write(c.ssl, data, (int)len);
  /*
   * Handle the errors.
   */
  if (ret <= 0) {
    auto err = SSL_get_error(c.ssl, ret);
    auto m = errorToString(err);
    m_log.error("SSL", "SSL_write error: ", m);
    return Status::ProtocolError;
  }
  /*
   * Handle partial data.
   */
  if (ret != (int)len) {
    m_log.error("SSL", "Partial SSL_write: ", ret, "/", len);
    return Status::IncompleteData;
  }
  /*
   * Update the offset.
   */
  off = ret;
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
Client::onConnected(ID const& id, void* const cookie)
{
  int keyfd = -1;
  /*
   * If we need to save keys, open the key file.
   */
  if (m_savekeys) {
    stack::ipv4::Address ip;
    stack::tcpv4::Port lport, rport;
    m_client->get(id, ip, lport, rport);
    auto path = ip.toString();
    path.append("_");
    path.append(std::to_string(lport));
    path.append("_");
    path.append(std::to_string(rport));
    path.append(".keys");
    keyfd = ::open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  }
  /*
   * Create the context.
   */
  auto* ssl = AS_SSL(m_context);
  auto* c = new Context(ssl, m_log, m_dev.mss(), id, cookie, keyfd);
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
  auto pre = c.state;
  /*
   * Write the data in the input BIO.
   */
  auto res = c.onNewData(id, m_delegate, data, len, alen, sdata, slen);
  auto post = c.state;
  /*
   * Check for the ready state transition.
   */
  if (pre == Context::State::Connect && post == Context::State::Ready) {
    c.cookie = m_delegate.onConnected(c.id, c.cookie);
  }
  /*
   * Done.
   */
  return res;
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
   * Check if there is any pending data.
   */
  size_t len = c.pending();
  if (len == 0) {
    return Status::Ok;
  }
  /*
   * Send the pending data.
   */
  uint32_t rem = 0;
  Status res = m_client->send(id, len, ssl::bio::readAt(c.bout), rem);
  if (res != Status::Ok) {
    c.blocked = res == Status::OperationInProgress;
    return res;
  }
  /*
   * Skip the processed data and return.
   */
  ssl::bio::skip(c.bout, rem);
  return Status::Ok;
}

}
