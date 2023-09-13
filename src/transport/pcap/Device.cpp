#include <tulips/stack/Ethernet.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/pcap/Device.h>

namespace tulips::transport::pcap {

static void
writePacket(pcap_dumper_t* const dumper, const void* const data,
            const size_t len, const system::Clock::Value ts)
{
  struct pcap_pkthdr hdr;
  system::Clock::Value secs = ts / system::Clock::SECOND;
#ifdef __OpenBSD__
  system::Clock::Value nscs = ts - secs * system::Clock::SECOND;
  hdr.ts.tv_sec = secs;
  hdr.ts.tv_usec = nscs / 1000ULL;
#else
  system::Clock::Value nscs = ts - secs * system::Clock::SECOND;
  hdr.ts.tv_sec = (time_t)secs;
  hdr.ts.tv_usec = (time_t)nscs;
#endif
  hdr.caplen = len;
  hdr.len = len;
  pcap_dump((u_char*)dumper, &hdr, (const u_char*)data);
}

Device::Device(system::Logger& log, transport::Device& device,
               std::string_view name)
  : transport::Device(log, "pcap")
  , m_device(device)
  , m_pcap(nullptr)
  , m_pcap_dumper(nullptr)
  , m_proc(nullptr)
{
  /*
   * We adapt the snapshot length to the lower link MSS. With TSO enabled, the
   * length of the IP packet is wrong if the payload is larger than 64K. It will
   * lead to invalid packets in the resulting PCAP.
   */
  uint32_t snaplen = m_device.mss() + stack::ethernet::HEADER_LEN;
  m_log.debug("PCAP", "snaplen is ", snaplen);
#ifdef __OpenBSD__
  m_pcap = pcap_open_dead(DLT_EN10MB, snaplen);
#else
  m_pcap = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, (int)snaplen,
                                                PCAP_TSTAMP_PRECISION_NANO);
#endif
  auto sfn = std::string(name) + ".pcap";
  m_pcap_dumper = pcap_dump_open(m_pcap, sfn.c_str());
}

Device::~Device()
{
  pcap_dump_flush(m_pcap_dumper);
  pcap_dump_close(m_pcap_dumper);
  pcap_close(m_pcap);
}

Status
Device::poll(Processor& proc)
{
  m_proc = &proc;
  return m_device.poll(*this);
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  m_proc = &proc;
  return m_device.wait(*this, ns);
}

Status
Device::prepare(uint8_t*& buf)
{
  return m_device.prepare(buf);
}

Status
Device::commit(const uint16_t len, uint8_t* const buf, const uint16_t mss)
{
  Status ret = m_device.commit(len, buf, mss);
  if (ret == Status::Ok) {
    writePacket(m_pcap_dumper, buf, len, system::Clock::read());
  }
  return ret;
}

Status
Device::release(uint8_t* const buf)
{
  return m_device.release(buf);
}

Status
Device::process(const uint16_t len, const uint8_t* const data,
                const Timestamp ts)
{
  if (len > 0) {
    writePacket(m_pcap_dumper, data, len, ts);
  }
  return m_proc->process(len, data, ts);
}

Status
Device::sent(const uint16_t len, uint8_t* const data)
{
  return m_proc->sent(len, data);
}

}
