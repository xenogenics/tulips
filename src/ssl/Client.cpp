#include <tulips/ssl/Client.h>
#include <tulips/ssl/Connection.h>
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
  void* d = SSL_get_app_data(ssl);
  auto* c = reinterpret_cast<tulips::ssl::Connection*>(d);
  if (c->keyFileDescriptor() != -1) {
    ::write(c->keyFileDescriptor(), line, strlen(line));
    ::write(c->keyFileDescriptor(), "\n", 1);
  }
}

}

namespace tulips::ssl {

Client::Client(system::Logger& log, api::interface::Client::Delegate& delegate,
               transport::Device& device, const Protocol type,
               const bool save_keys, const size_t nconn,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& gw,
               stack::ipv4::Address const& nm)
  : m_delegate(delegate)
  , m_log(log)
  , m_client(log, *this, device, nconn, ip, gw, nm)
  , m_ssl(nullptr)
  , m_nconn(nconn)
  , m_savekeys(save_keys)
  , m_cns()
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
   * Create the SSL connection.
   */
  long flags = 0;
  m_ssl = SSL_CTX_new(ssl::getMethod(type, false, flags));
  if (m_ssl == nullptr) {
    throw std::runtime_error("SSL_CTX_new failed");
  }
  SSL_CTX_set_options(AS_SSL(m_ssl), flags);
  SSL_CTX_set_keylog_callback(AS_SSL(m_ssl), keylogCallback);
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
  m_cns.resize(nconn);
}

Client::Client(system::Logger& log, api::interface::Client::Delegate& delegate,
               transport::Device& device, const Protocol type,
               std::string_view cert, std::string_view key, const size_t nconn,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& gw,
               stack::ipv4::Address const& nm)
  : Client(log, delegate, device, type, true, nconn, ip, gw, nm)
{
  int err = 0;
  /*
   * Load certificate and private key files, and check consistency.
   */
  auto scert = std::string(cert);
  err = SSL_CTX_use_certificate_file(AS_SSL(m_ssl), scert.c_str(),
                                     SSL_FILETYPE_PEM);
  if (err != 1) {
    throw std::runtime_error("SSL_CTX_use_certificate_file failed");
  }
  m_log.info("SSLCLI", "using certificate: ", cert);
  /*
   * Indicate the key file to be used.
   */
  auto skey = std::string(key);
  err =
    SSL_CTX_use_PrivateKey_file(AS_SSL(m_ssl), skey.c_str(), SSL_FILETYPE_PEM);
  if (err != 1) {
    throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed");
  }
  m_log.info("SSLCLI", "using key: ", key);
  /*
   * Make sure the key and certificate file match.
   */
  if (SSL_CTX_check_private_key(AS_SSL(m_ssl)) != 1) {
    throw std::runtime_error("SSL_CTX_check_private_key failed");
  }
}

Client::~Client()
{
  SSL_CTX_free(AS_SSL(m_ssl));
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
   * Check if the connection is in the right state.
   */
  if (c.state() != Connection::State::Ready &&
      c.state() != Connection::State::Shutdown) {
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
      return m_client.close(id);
    }
    default: {
      return ret;
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
   * Perform the handshake.
   */
  switch (c.state()) {
    /*
     * Connection is closed.
     */
    case Connection::State::Closed: {
      Status res = m_client.connect(id, ripaddr, rport);
      if (res != Status::Ok) {
        return res;
      }
      [[fallthrough]];
    }
    /*
     * Start the SSL handshake.
     */
    case Connection::State::Open: {
      /*
       * Get the client's host name.
       */
      std::optional<std::string> hostname;
      m_client.getHostName(id, hostname);
      /*
       * Get the client's application layer protocol.
       */
      auto alp = m_client.applicationLayerProtocol(id);
      /*
       * Start the handshake.
       */
      auto ret = c.connect(m_log, id, hostname, alp);
      /*
       * Flush any pending data.
       */
      if (ret == Status::OperationInProgress) {
        Status res = flush(id);
        if (res != Status::Ok) {
          return res;
        }
      }
      /*
       * Done.
       */
      return ret;
    }
    /*
     * Connection is connecting.
     */
    case Connection::State::Connecting: {
      return Status::OperationInProgress;
    }
    /*
     * Connection is connected.
     *
     * NOTE(xrg): the ordering below is important.
     */
    case Connection::State::Connected: {
      c.setReady();
      c.setCookie(m_delegate.onConnected(id, c.cookie(), c.timestamp()));
      return Status::Ok;
    }
    /*
     * Connection is accepting.
     */
    case Connection::State::Accepting: {
      return Status::ProtocolError;
    }
    /*
     * Connection is ready.
     */
    case Connection::State::Ready: {
      return Status::Ok;
    }
    /*
     * Connection is being shut down.
     */
    case Connection::State::Shutdown: {
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
Client::get(const ID id, stack::ipv4::Address& laddr, stack::tcpv4::Port& lport,
            stack::ipv4::Address& raddr, stack::tcpv4::Port& rport) const
{
  return m_client.get(id, laddr, lport, raddr, rport);
}

Status
Client::send(const ID id, const uint32_t len, const uint8_t* const data,
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
  auto& c = m_cns[id];
  /*
   * Skip if the length is 0.
   */
  if (len == 0) {
    return Status::InvalidArgument;
  }
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
    std::string path;
    stack::ipv4::Address laddr, raddr;
    stack::tcpv4::Port lport, rport;
    m_client.get(id, laddr, lport, raddr, rport);
    path.append(laddr.toString());
    path.append(":");
    path.append(std::to_string(lport));
    path.append("_");
    path.append(raddr.toString());
    path.append(":");
    path.append(std::to_string(rport));
    path.append(".keys");
    keyfd = ::open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  }
  /*
   * Open the connection.
   */
  auto* ssl = AS_SSL(m_ssl);
  m_cns[id].open(ssl, id, cookie, ts, keyfd);
  /*
   * Done.
   */
  return nullptr;
}

Action
Client::onAcked(ID const& id, [[maybe_unused]] void* const cookie,
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
Client::onAcked(ID const& id, [[maybe_unused]] void* const cookie,
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
Client::onNewData(ID const& id, [[maybe_unused]] void* const cookie,
                  const uint8_t* const data, const uint32_t len,
                  const Timestamp ts)
{
  /*
   * Grab the connection.
   */
  auto& c = m_cns[id];
  /*
   * Decrypt the incoming data.
   */
  return c.onNewData(m_log, id, m_delegate, data, len, ts);
}

Action
Client::onNewData(ID const& id, [[maybe_unused]] void* const cookie,
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
Client::onClosed(ID const& id, [[maybe_unused]] void* const cookie,
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
Client::flush(const ID id)
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
  Status res = m_client.send(id, len, c.readAt(), rem);
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
