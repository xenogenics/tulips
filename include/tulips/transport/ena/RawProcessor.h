#include <tulips/system/CircularBuffer.h>
#include <tulips/system/SpinLock.h>
#include <tulips/transport/Processor.h>
#include <vector>

namespace tulips::transport::ena {

class RawProcessor : public transport::Processor
{
public:
  Status run() override { return Status::Ok; }
  Status process(const uint16_t len, const uint8_t* const data) override;

  void add(system::CircularBuffer::Ref const& buffer);

private:
  system::SpinLock m_lock;
  std::vector<system::CircularBuffer::Ref> m_buffers;
};

}
