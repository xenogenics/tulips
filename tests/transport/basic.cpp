#include <tulips/stack/Ethernet.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/shm/Device.h>
#include <cstddef>
#include <gtest/gtest.h>

using namespace tulips;

namespace {

constexpr size_t ITERATIONS = 1000;

class ClientProcessor : public transport::Processor
{
public:
  ClientProcessor() : m_value(1), m_do(true), m_prod(nullptr) {}

  Status run() override
  {
    if (m_do) {
      uint8_t* data;
      m_prod->prepare(data);
      memcpy(data, &m_value, sizeof(size_t));
      m_do = false;
      return m_prod->commit(sizeof(m_value), data);
    }
    return Status::Ok;
  }

  Status process(const uint16_t len, const uint8_t* const data) override
  {
    size_t value;
    memcpy(&value, data, sizeof(size_t));
    if (len == sizeof(m_value) && value == m_value) {
      m_value += 1;
      m_do = true;
      return Status::Ok;
    }
    return Status::IncompleteData;
  }

  size_t value() const { return m_value; }

  ClientProcessor& setProducer(transport::Producer& prod)
  {
    m_prod = &prod;
    return *this;
  }

private:
  size_t m_value;
  bool m_do;
  transport::Producer* m_prod;
};

class ServerProcessor : public transport::Processor
{
public:
  ServerProcessor() : m_value(0), m_prod(nullptr) {}

  Status run() override { return Status::Ok; }

  Status process(UNUSED const uint16_t len, const uint8_t* const data) override
  {
    memcpy(&m_value, data, sizeof(size_t));
    uint8_t* outdata;
    m_prod->prepare(outdata);
    memcpy(outdata, &m_value, sizeof(size_t));
    return m_prod->commit(sizeof(m_value), outdata);
  }

  size_t value() const { return m_value; }

  ServerProcessor& setProducer(transport::Producer& prod)
  {
    m_prod = &prod;
    return *this;
  }

private:
  size_t m_value;
  transport::Producer* m_prod;
};

void*
client_thread(void* arg)
{
  transport::shm::Device& client =
    *reinterpret_cast<transport::shm::Device*>(arg);
  ClientProcessor proc;
  proc.setProducer(client);
  while (proc.value() <= ITERATIONS) {
    if (client.poll(proc) == Status::NoDataAvailable) {
      proc.run();
    }
  }
  return nullptr;
}

void*
server_thread(void* arg)
{
  transport::shm::Device& server =
    *reinterpret_cast<transport::shm::Device*>(arg);
  ServerProcessor proc;
  proc.setProducer(server);
  while (proc.value() < ITERATIONS) {
    if (server.poll(proc) == Status::NoDataAvailable) {
      proc.run();
    }
  }
  return nullptr;
}

} // namespace

TEST(Transport_Basic, SharedMemory)
{
  tulips_fifo_t client_fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_t server_fifo = TULIPS_FIFO_DEFAULT_VALUE;
  /*
   * Build the FIFOs
   */
  tulips_fifo_create(64, 32, &client_fifo);
  tulips_fifo_create(64, 32, &server_fifo);
  /*
   * Build the devices
   */
  stack::ethernet::Address client_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10);
  stack::ethernet::Address server_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20);
  stack::ipv4::Address client_ip4(10, 1, 0, 1);
  stack::ipv4::Address server_ip4(10, 1, 0, 2);
  stack::ipv4::Address bcast(10, 1, 0, 254);
  stack::ipv4::Address nmask(255, 255, 255, 0);
  transport::shm::Device client(client_adr, client_ip4, bcast, nmask,
                                server_fifo, client_fifo);
  transport::shm::Device server(server_adr, server_ip4, bcast, nmask,
                                client_fifo, server_fifo);
  /*
   * Start the threads
   */
  pthread_t t0, t1;
  pthread_create(&t0, nullptr, client_thread, &client);
  pthread_create(&t1, nullptr, server_thread, &server);
  /*
   * Wait for the threads
   */
  pthread_join(t0, nullptr);
  pthread_join(t1, nullptr);
  /*
   * Destroy the FIFOs
   */
  tulips_fifo_destroy(&client_fifo);
  tulips_fifo_destroy(&server_fifo);
}
