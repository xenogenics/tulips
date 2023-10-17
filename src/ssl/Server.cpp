#include <tulips/ssl/Connection.h>
#include <tulips/ssl/Server.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace tulips::ssl {

Server::Server(system::Logger& log, api::interface::Server::Delegate& delegate,
               transport::Device& device, const size_t n,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& gw,
               stack::ipv4::Address const& nm, const ssl::Protocol type,
               std::string_view cert, std::string_view key)
  : m_delegate(delegate)
  , m_log(log)
  , m_server(std::make_unique<api::Server>(log, *this, device, n, ip, gw, nm))
  , m_nconn(n)
  , m_ssl(nullptr)
  , m_cns()
{
  int err = 0;
  m_log.debug("SSLSRV", "protocol: ", ssl::toString(type));
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
  m_ssl = SSL_CTX_new(ssl::getMethod(type, true, flags));
  if (m_ssl == nullptr) {
    throw std::runtime_error("SSL_CTX_new failed");
  }
  SSL_CTX_set_options(AS_SSL(m_ssl), flags);
  /*
   * Load certificate and private key files, and check consistency.
   */
  auto scert = std::string(cert);
  err = SSL_CTX_use_certificate_file(AS_SSL(m_ssl), scert.c_str(),
                                     SSL_FILETYPE_PEM);
  if (err != 1) {
    throw std::runtime_error("SSL_CTX_use_certificate_file failed");
  }
  m_log.debug("SSLSRV", "using certificate: ", cert);
  /*
   * Indicate the key file to be used.
   */
  auto skey = std::string(key);
  err =
    SSL_CTX_use_PrivateKey_file(AS_SSL(m_ssl), skey.c_str(), SSL_FILETYPE_PEM);
  if (err != 1) {
    throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed");
  }
  m_log.debug("SSLSRV", "using key: ", key);
  /*
   * Make sure the key and certificate file match.
   */
  if (SSL_CTX_check_private_key(AS_SSL(m_ssl)) != 1) {
    throw std::runtime_error("SSL_CTX_check_private_key failed");
  }
  /*
   * Use AES ciphers.
   */
  const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!PSK:!SRP:!MD5:!RC4:!3DES";
  int res = SSL_CTX_set_cipher_list(AS_SSL(m_ssl), PREFERRED_CIPHERS);
  if (res != 1) {
    throw std::runtime_error("SSL_CTX_set_cipher_list failed");
  }
  /*
   * Resize the connections.
   */
  m_cns.resize(n);
}

Server::~Server()
{
  SSL_CTX_free(AS_SSL(m_ssl));
}

Status
Server::close(const ID id)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  /*
   * Shutdown the connection.
   */
  switch (auto ret = c.shutdown(m_log, id)) {

    case Status::OperationInProgress: {
      flush(id);
      return Status::OperationInProgress;
    }
    case Status::OperationCompleted: {
      return m_server->close(id);
    }
    default: {
      return ret;
    }
  }
}

bool
Server::isClosed(const ID id) const
{
  return m_server->isClosed(id);
}

Status
Server::send(const ID id, const uint32_t len, const uint8_t* const data,
             uint32_t& off)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  /*
   * Grab the connection.
   */
  Connection& c = m_cns[id];
  /*
   * Write the data.
   */
  auto ret = c.write(m_log, id, len, data);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Update the offset to the data length as the BIO never fails.
   */
  off = len;
  /*
   * Flush the data.
   */
  return flush(id);
}

void*
Server::onConnected(ID const& id, void* const cookie, const Timestamp ts)
{
  auto* ssl = AS_SSL(m_ssl);
  m_cns[id].accept(ssl, id, cookie, ts, -1);
  return nullptr;
}

Action
Server::onAcked(ID const& id, [[maybe_unused]] void* const cookie,
                const Timestamp ts)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  /*
   * Return if the handshake was not done.
   */
  if (c.state() != Connection::State::Ready) {
    return Action::Continue;
  }
  /*
   * Notify the delegate.
   */
  return m_delegate.onAcked(id, c.cookie(), ts);
}

Action
Server::onAcked(ID const& id, [[maybe_unused]] void* const cookie,
                const Timestamp ts, const uint32_t alen, uint8_t* const sdata,
                uint32_t& slen)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  /*
   * If the BIO has data pending, flush it.
   */
  return c.onAcked(m_log, id, m_delegate, ts, alen, sdata, slen);
}

Action
Server::onNewData(ID const& id, [[maybe_unused]] void* const cookie,
                  const uint8_t* const data, const uint32_t len,
                  const Timestamp ts)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  /*
   * Process the incoming data.
   */
  return c.onNewData(m_log, id, m_delegate, data, len, ts);
}

Action
Server::onNewData(ID const& id, [[maybe_unused]] void* const cookie,
                  const uint8_t* const data, const uint32_t len,
                  const Timestamp ts, const uint32_t alen, uint8_t* const sdata,
                  uint32_t& slen)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  /*
   * Write the data in the input BIO.
   */
  return c.onNewData(m_log, id, m_delegate, data, len, ts, alen, sdata, slen);
}

void
Server::onClosed(ID const& id, [[maybe_unused]] void* const cookie,
                 const Timestamp ts)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  auto* d = c.cookie();
  /*
   * Close the connection.
   */
  c.close();
  /*
   * Notify the delegate.
   */
  m_delegate.onClosed(id, d, ts);
}

Status
Server::flush(const ID id)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
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
  Status res = m_server->send(id, len, c.readAt(), rem);
  if (res != Status::Ok) {
    c.setBlocked(res == Status::OperationInProgress);
    return res;
  }
  /*
   * Skip the processed data and return.
   */
  c.consume(rem);
  return Status::Ok;
}

}
