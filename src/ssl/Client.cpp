#include "Context.h"
#include <tulips/ssl/Client.h>
#include <tulips/stack/IPv4.h>
#include <tulips/stack/Utils.h>
#include <cstdint>
#include <stdexcept>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
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
  , m_client(log, *this, device, nconn)
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

bool
Client::live() const
{
  return m_client.live();
}

Status
Client::open(const ApplicationLayerProtocol alpn, const uint8_t options, ID& id)
{
  return m_client.open(alpn, options, id);
}

Status
Client::abort(const ID id)
{
  /*
   * Grab the context.
   */
  void* cookie = m_client.cookie(id);
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
  return m_client.abort(id);
}

Status
Client::close(const ID id)
{
  /*
   * Grab the context.
   */
  void* cookie = m_client.cookie(id);
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
      return m_client.close(id);
    }
    default: {
      auto err = SSL_get_error(c.ssl, ret);
      auto error = ssl::errorToString(err);
      m_log.error("SSLCLI", "SSL_shutdown error: ", error);
      return Status::ProtocolError;
    }
  }
}

Status
Client::setHostName(const ID id, std::string_view hn)
{
  return m_client.setHostName(id, hn);
}

Status
Client::getHostName(const ID id, std::optional<std::string>& hn)
{
  return m_client.getHostName(id, hn);
}

Status
Client::connect(const ID id, stack::ipv4::Address const& ripaddr,
                const stack::tcpv4::Port rport)
{

  void* cookie = m_client.cookie(id);
  /*
   * If the cookie is nullptr, we are not connected yet.
   */
  if (cookie == nullptr) {
    Status res = m_client.connect(id, ripaddr, rport);
    if (res != Status::Ok) {
      return res;
    }
    cookie = m_client.cookie(id);
  }
  /*
   * Perform the handshake.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  switch (c.state) {
    /*
     * Context is closed.
     */
    case Context::State::Closed: {
      return Status::NotConnected;
    }
    /*
     * Start the SSL handshake.
     */
    case Context::State::Open: {
      /*
       * Get the client's host name.
       */
      std::optional<std::string> hostname;
      m_client.getHostName(id, hostname);
      /*
       * Set the host name for SNI-enabled servers.
       */
      if (hostname.has_value()) {
        SSL_set_tlsext_host_name(c.ssl, hostname.value().c_str());
      }
      /*
       * Apply the application layer protocol.
       */
      switch (m_client.applicationLayerProtocol(id)) {
        case ApplicationLayerProtocol::None: {
          break;
        }
        case ApplicationLayerProtocol::HTTP_1_1: {
          static uint8_t name[] = "\x08http/1.1";
          if (SSL_set_alpn_protos(c.ssl, name, 9)) {
            m_log.error("SSLCLI", "failed to set ALPN for HTTP/1.1");
            return Status::ProtocolError;
          };
          break;
        }
        case ApplicationLayerProtocol::HTTP_2: {
          static uint8_t name[] = "\x02h2";
          if (SSL_set_alpn_protos(c.ssl, name, 3)) {
            m_log.error("SSLCLI", "failed to set ALPN for HTTP/2");
            return Status::ProtocolError;
          };
          break;
        }
      }
      /*
       * Connect.
       */
      if (SSL_connect(c.ssl) != -1) {
        m_log.error("SSLCLI", "connect error");
        return Status::ProtocolError;
      }
      /*
       * Check the error.
       */
      auto err = SSL_get_error(c.ssl, -1);
      if (err != SSL_ERROR_WANT_READ) {
        auto error = ssl::errorToString(err);
        m_log.error("SSLCLI", "connect error: ", error);
        return Status::ProtocolError;
      }
      /*
       * Flush any pending data.
       */
      Status res = flush(id, cookie);
      if (res != Status::Ok) {
        return res;
      }
      /*
       * Update the state and return.
       */
      c.state = Context::State::Connecting;
      return Status::OperationInProgress;
    }
    /*
     * Context is connecting.
     */
    case Context::State::Connecting: {
      return Status::OperationInProgress;
    }
    /*
     * Context is accepting.
     */
    case Context::State::Accepting: {
      return Status::ProtocolError;
    }
    /*
     * Context is connected.
     */
    case Context::State::Connected: {
      c.state = Context::State::Ready;
      c.cookie = m_delegate.onConnected(c.id, c.cookie, c.ts);
      return Status::Ok;
    }
    /*
     * Context is ready.
     */
    case Context::State::Ready: {
      return Status::Ok;
    }
    /*
     * Context is being shut down.
     */
    case Context::State::Shutdown: {
      return Status::InvalidArgument;
    }
  }
    /*
     * Make GCC happy.
     */
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
  return Status::Ok;
#endif
}

bool
Client::isClosed(const ID id) const
{
  return m_client.isClosed(id);
}

Status
Client::get(const ID id, stack::ipv4::Address& ripaddr,
            stack::tcpv4::Port& lport, stack::tcpv4::Port& rport) const
{
  return m_client.get(id, ripaddr, lport, rport);
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
  void* cookie = m_client.cookie(id);
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
  return m_client.averageLatency(id);
}

void*
Client::onConnected(ID const& id, void* const cookie, const Timestamp ts)
{
  int keyfd = -1;
  /*
   * If we need to save keys, open the key file.
   */
  if (m_savekeys) {
    stack::ipv4::Address ip;
    stack::tcpv4::Port lport, rport;
    m_client.get(id, ip, lport, rport);
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
  auto* c = new Context(ssl, m_log, id, cookie, ts, keyfd);
  c->state = Context::State::Open;
  return c;
}

Action
Client::onAcked(ID const& id, void* const cookie, const Timestamp ts)
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
  return m_delegate.onAcked(id, c.cookie, ts);
}

Action
Client::onAcked(ID const& id, void* const cookie, const Timestamp ts,
                const uint32_t alen, uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * If the BIO has data pending, flush it.
   */
  return c.onAcked(id, m_delegate, ts, alen, sdata, slen);
}

Action
Client::onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                  const uint32_t len, const Timestamp ts)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Decrypt the incoming data.
   */
  return c.onNewData(id, m_delegate, data, len, ts);
}

Action
Client::onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                  const uint32_t len, const Timestamp ts, const uint32_t alen,
                  uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Grab the context.
   */
  Context& c = *reinterpret_cast<Context*>(cookie);
  /*
   * Write the data in the input BIO.
   */
  return c.onNewData(id, m_delegate, data, len, ts, alen, sdata, slen);
}

void
Client::onClosed(ID const& id, void* const cookie, const Timestamp ts)
{
  auto* c = reinterpret_cast<Context*>(cookie);
  if (c != nullptr) {
    m_delegate.onClosed(id, c->cookie, ts);
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
  size_t len = c.pendingRead();
  if (len == 0) {
    return Status::Ok;
  }
  /*
   * Send the pending data.
   */
  uint32_t rem = 0;
  Status res = m_client.send(id, len, ssl::bio::readAt(c.bout), rem);
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
