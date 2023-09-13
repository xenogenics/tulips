#include "Utils.h"
#include "tulips/fifo/fifo.h"
#include <tulips/fifo/errors.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/Utils.h>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>

/*
 * Enable OFED_CAPTSOB to limit the TSO segment to 64KB. This is required to
 * debug large segment with the PCAP transport enabled as IP packets cannot be
 * larger than 64KB.
 */
#define OFED_CAPTSOB 0 // NOLINT

namespace tulips::transport::ofed {

Device::Device(system::Logger& log, const uint16_t nbuf)
  : transport::Device(log, "ofed")
  , m_nbuf(nbuf)
  , m_pending(0)
  , m_port(0)
  , m_context(nullptr)
  , m_address()
  , m_ip()
  , m_dr()
  , m_nm()
  , m_hwmtu(0)
  , m_mtu(0)
  , m_buflen(0)
  , m_pd(nullptr)
  , m_comp(nullptr)
  , m_events(0)
  , m_sendcq(nullptr)
  , m_recvcq(nullptr)
  , m_qp(nullptr)
  , m_sendbuf(nullptr)
  , m_recvbuf(nullptr)
  , m_sendmr(nullptr)
  , m_recvmr(nullptr)
  , m_free(TULIPS_FIFO_DEFAULT_VALUE)
  , m_sent(TULIPS_FIFO_DEFAULT_VALUE)
  , m_bcast(nullptr)
  , m_flow(nullptr)
  , m_filters()
{
  std::string ifn;
  /*
   * Find a valid interface
   */
  if (!findSupportedInterface(ifn)) {
    throw std::runtime_error("No supported interface found");
  }
  /*
   * Construct the device.
   */
  this->m_name = ifn;
  construct(ifn, nbuf);
}

Device::Device(system::Logger& log, std::string_view ifn, const uint16_t nbuf)
  : transport::Device(log, ifn)
  , m_nbuf(nbuf)
  , m_pending(0)
  , m_port(0)
  , m_context(nullptr)
  , m_address()
  , m_ip()
  , m_dr()
  , m_nm()
  , m_hwmtu(0)
  , m_mtu(0)
  , m_buflen(0)
  , m_pd(nullptr)
  , m_comp(nullptr)
  , m_events(0)
  , m_sendcq(nullptr)
  , m_recvcq(nullptr)
  , m_qp(nullptr)
  , m_sendbuf(nullptr)
  , m_recvbuf(nullptr)
  , m_sendmr(nullptr)
  , m_recvmr(nullptr)
  , m_free(TULIPS_FIFO_DEFAULT_VALUE)
  , m_sent(TULIPS_FIFO_DEFAULT_VALUE)
  , m_bcast(nullptr)
  , m_flow(nullptr)
  , m_filters()
{
  /*
   * Check if the interface driver is mlx?_core.
   */
  if (!isSupportedDevice(ifn)) {
    throw std::runtime_error("Unsupported interface: " + m_name);
  }
  /*
   * Construct the device.
   */
  this->m_name = ifn;
  construct(ifn, nbuf);
}

void
Device::construct(std::string_view ifn, UNUSED const uint16_t nbuf)
{
  int res, ndev = 0;
  ibv_device** devlist = ibv_get_device_list(&ndev);
  /*
   * Check if there are any device available.
   */
  m_log.debug("OFED", "using network interface: ", ifn);
  if (ndev == 0) {
    ibv_free_device_list(devlist);
    throw std::runtime_error("No OFED-compatible device found");
  }
  /*
   * Get the device id and the port id.
   */
  std::string devname;
  if (!getInterfaceDeviceAndPortIds(ifn, devname, m_port)) {
    throw std::runtime_error("Cannot get device and port IDs");
  }
  /*
   * Take the one that matches our the provided name.
   */
  ibv_device* device = nullptr;
  for (int i = 0; i < ndev; i += 1) {
    if (devname == devlist[i]->name) {
      device = devlist[i];
      break;
    }
  }
  if (device == nullptr) {
    ibv_free_device_list(devlist);
    throw std::runtime_error("Requested device not found");
  }
  m_log.debug("OFED", "name: ", device->name);
  m_log.debug("OFED", "dev_name: ", device->dev_name);
  m_log.debug("OFED", "dev_path: ", device->dev_path);
  m_log.debug("OFED", "ibdev_path: ", device->ibdev_path);
  /*
   * Get lladdr and MTU.
   */
  if (!utils::getInterfaceInformation(m_log, ifn, m_address, m_hwmtu)) {
    throw std::runtime_error("Cannot read device's lladdr and mtu");
  }
  m_log.debug("OFED", "hardware address: ", m_address.toString());
  m_log.debug("OFED", "MTU: ", m_hwmtu);
  m_mtu = m_hwmtu;
  m_buflen = m_hwmtu + stack::ethernet::HEADER_LEN;
  m_log.debug("OFED", "send buffer length: ", m_buflen);
  /*
   * Get L3 addresses.
   */
  if (!utils::getInterfaceInformation(m_log, ifn, m_ip, m_nm, m_dr)) {
    throw std::runtime_error("Cannot read device's L3 addresses");
  }
  m_log.debug("OFED", "ip address: ", m_ip.toString());
  m_log.debug("OFED", "netmask: ", m_nm.toString());
  m_log.debug("OFED", "router address: ", m_dr.toString());
  /*
   * Open the device.
   */
  m_context = ibv_open_device(device);
  if (m_context == nullptr) {
    throw std::runtime_error("Cannot open device");
  }
  /*
   * Query the device for its MAC.
   */
  struct ibv_device_attr_ex deva;
  res = ibv_query_device_ex(m_context, nullptr, &deva);
  if (res != 0) {
    std::string error(strerror(res));
    throw std::runtime_error("Cannot query device: " + error);
  }
  /*
   * Find out the capabilities.
   */
  PRINT_EXP_CAP(deva, IBV_DEVICE_MANAGED_FLOW_STEERING);
  PRINT_EXP_CAP(deva, IBV_DEVICE_RAW_IP_CSUM);
  /*
   * In case we are compiled with HW checksum support, make sure it is
   * supported.
   */
#ifdef TULIPS_HAS_HW_CHECKSUM
  if (!(deva.device_cap_flags_ex & IBV_DEVICE_RAW_IP_CSUM)) {
#ifdef TULIPS_IGNORE_INCOMPATIBLE_HW
    m_log.error("OFED", "IP checksum offload not supported by device, ignored");
#else
    throw std::runtime_error("Device does not support IP checksum offload");
#endif
  }
#endif
  /*
   * In case we are compiled with HW TSO, makes sure it is supported.
   */
#ifdef TULIPS_HAS_HW_TSO
  if (HAS_TSO(deva.tso_caps)) {
    m_log.debug("OFED", "max TSO length: " << deva.tso_caps.max_tso);
#if OFED_CAPTSOB
    m_buflen = 65536;
    m_log.debug("OFED", "updated limit send buffer length: " << m_buflen);
#else
    m_buflen = deva.tso_caps.max_tso;
    m_log.debug("OFED", "updated send buffer length: " << m_buflen);
#endif
  } else {
#ifdef TULIPS_IGNORE_INCOMPATIBLE_HW
    m_log.error("OFED", "TSO not supported by device, ignored");
#else
    throw std::runtime_error("Device does not support TSO");
#endif
  }
#endif
  /*
   * Query the device port.
   */
  struct ibv_port_attr pattr;
  res = ibv_query_port(m_context, m_port + 1, &pattr);
  if (res != 0) {
    std::string error(strerror(res));
    throw std::runtime_error("Cannot query port: " + error);
  }
  /*
   * Allocate a protection domain.
   */
  m_pd = ibv_alloc_pd(m_context);
  if (m_pd == nullptr) {
    throw std::runtime_error("Cannot allocate protection domain");
  }
  /*
   * Setup the CQ, QP, etc...
   */
  setup(m_context, m_pd, m_port, m_nbuf, m_buflen, RECV_BUFLEN, m_comp,
        m_sendcq, m_recvcq, m_qp, m_sendbuf, m_recvbuf, m_sendmr, m_recvmr);
  /*
   * Prepare the receive buffers.
   */
  for (uint16_t i = 0; i < m_nbuf; i += 1) {
    if (postReceive(i) != Status::Ok) {
      throw std::runtime_error("Cannot post receive buffer");
    }
  }
  /*
   * Create the send FIFO.
   */
  tulips_fifo_create(m_nbuf, sizeof(uint8_t*), &m_free);
  tulips_fifo_create(m_nbuf, sizeof(uint8_t*), &m_sent);
  /*
   * Fill the send FIFO.
   */
  for (int i = 0; i < m_nbuf; i += 1) {
    uint8_t* address = m_sendbuf + i * m_buflen;
    tulips_fifo_push(m_free, &address);
  }
  /*
   * Define the raw flow attribute structure.
   */
#if defined(TULIPS_ENABLE_ARP) || defined(TULIPS_ENABLE_RAW)
  struct raw_eth_flow_attr
  {
    struct ibv_flow_attr attr;
    struct ibv_flow_spec_eth spec_eth;
  } PACKED;
  /*
   * Fill in the attributes.
   */
  struct raw_eth_flow_attr flow;
  memset(&flow, 0, sizeof(flow));
  //
  flow.attr.type = IBV_FLOW_ATTR_NORMAL;
  flow.attr.size = sizeof(flow);
  flow.attr.num_of_specs = 1;
  flow.attr.port = m_port + 1;
  //
  flow.spec_eth.type = IBV_FLOW_SPEC_ETH;
  flow.spec_eth.size = sizeof(struct ibv_flow_spec_eth);
  /*
   * Create the broadcast flow.
   */
#ifdef TULIPS_ENABLE_ARP
  memset(flow.spec_eth.val.dst_mac, 0xFF, 6);
  memset(flow.spec_eth.mask.dst_mac, 0xFF, 6);
  m_bcast = ibv_create_flow(m_qp, (ibv_flow_attr*)&flow);
  if (m_bcast == nullptr) {
    throw std::runtime_error("Cannot create broadcast flow");
  }
#endif
  /*
   * Setup the local MAC flow.
   */
  memcpy(flow.spec_eth.val.dst_mac, m_address.data(), 6);
  memset(flow.spec_eth.mask.dst_mac, 0xFF, 6);
  m_flow = ibv_create_flow(m_qp, (ibv_flow_attr*)&flow);
  if (m_flow == nullptr) {
    throw std::runtime_error("Cannot create unicast flow");
  }
#endif
}

Status
Device::postReceive(const uint16_t id)
{
  struct ibv_sge sge;
  struct ibv_recv_wr wr;
  const uint8_t* addr = m_recvbuf + size_t(id) * RECV_BUFLEN;
  /*
   * SGE entry.
   */
  sge.addr = (uint64_t)addr;
  sge.length = RECV_BUFLEN;
  sge.lkey = m_recvmr->lkey;
  /*
   * Work request.
   */
  wr.wr_id = id;
  wr.next = nullptr;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  /*
   * Post the received the buffer list.
   */
  struct ibv_recv_wr* bad_wr;
  if (ibv_post_recv(m_qp, &wr, &bad_wr) != 0) {
    m_log.error("OFED", "post receive of buffer id=", id, "failed");
    return Status::HardwareError;
  }
  return Status::Ok;
}

Device::~Device()
{
  /*
   * Destroy dynamic flows.
   */
  for (auto& m_filter : m_filters) {
    ibv_destroy_flow(m_filter.second);
  }
  m_filters.clear();
  /*
   * Destroy static flows.
   */
  if (m_flow) {
    ibv_destroy_flow(m_flow);
  }
  if (m_bcast) {
    ibv_destroy_flow(m_bcast);
  }
  /*
   * Clean-up all CQ events.
   */
  ibv_cq* cq = nullptr;
  void* context = nullptr;
  if (ibv_get_cq_event(m_comp, &cq, &context) == 0) {
    m_events += 1;
  }
  ibv_ack_cq_events(m_recvcq, m_events);
  /*
   * Free the FIFOs.
   */
  tulips_fifo_destroy(&m_sent);
  tulips_fifo_destroy(&m_free);
  /*
   * Destroy memory regions
   */
  if (m_sendmr) {
    ibv_dereg_mr(m_sendmr);
  }
  if (m_sendbuf) {
    munmap(m_sendbuf, m_nbuf * m_buflen);
  }
  if (m_recvmr) {
    ibv_dereg_mr(m_recvmr);
  }
  if (m_recvbuf) {
    munmap(m_recvbuf, size_t(m_nbuf) * RECV_BUFLEN);
  }
  /*
   * Destroy queue pair
   */
  if (m_qp) {
    ibv_destroy_qp(m_qp);
  }
  if (m_sendcq) {
    ibv_destroy_cq(m_sendcq);
  }
  if (m_recvcq) {
    ibv_destroy_cq(m_recvcq);
  }
  if (m_comp) {
    ibv_destroy_comp_channel(m_comp);
  }
  if (m_pd) {
    ibv_dealloc_pd(m_pd);
  }
  if (m_context) {
    ibv_close_device(m_context);
  }
}

Status
Device::listen(const stack::ipv4::Protocol proto, const uint16_t lport,
               UNUSED stack::ipv4::Address const& raddr,
               UNUSED const uint16_t rport)
{
  /*
   * Skip if the protocol is ICMP.
   */
  if (proto == stack::ipv4::Protocol::ICMP) {
    return Status::Ok;
  }
  /*
   * Only TCP is supported for now.
   */
  if (proto != stack::ipv4::Protocol::TCP) {
    return Status::UnsupportedProtocol;
  }
  /*
   * Define the TCP flow attribute structure.
   */
  struct tcp_flow_attr
  {
    struct ibv_flow_attr atr;
    struct ibv_flow_spec_eth l2;
    struct ibv_flow_spec_ipv4 l3;
    struct ibv_flow_spec_tcp_udp l4;
  } PACKED;
  /*
   * Fill in the attributes.
   */
  struct tcp_flow_attr flow;
  memset(&flow, 0, sizeof(flow));
  //
  flow.atr.type = IBV_FLOW_ATTR_NORMAL;
  flow.atr.size = sizeof(flow);
  flow.atr.num_of_specs = 3;
  flow.atr.port = m_port + 1;
  //
  flow.l2.type = IBV_FLOW_SPEC_ETH;
  flow.l2.size = sizeof(struct ibv_flow_spec_eth);
  memcpy(flow.l2.val.dst_mac, m_address.data(), 6);
  memset(flow.l2.mask.dst_mac, 0xFF, 6);
  //
  flow.l3.type = IBV_FLOW_SPEC_IPV4;
  flow.l3.size = sizeof(struct ibv_flow_spec_ipv4);
  memcpy(&flow.l3.val.dst_ip, m_ip.data(), 4);
  memset(&flow.l3.mask.dst_ip, 0xFF, 4);
  //
  flow.l4.type = IBV_FLOW_SPEC_TCP;
  flow.l4.size = sizeof(struct ibv_flow_spec_tcp_udp);
  flow.l4.val.dst_port = htons(lport);
  flow.l4.mask.dst_port = 0xFFFF;
  /*
   * Setup the TCP flow.
   */
  ibv_flow* f = ibv_create_flow(m_qp, (ibv_flow_attr*)&flow);
  if (f == nullptr) {
    m_log.error("OFED", "cannot create TCP/UDP FLOW");
    return Status::HardwareError;
  }
  /*
   * Register the flow.
   */
  m_log.debug("OFED", "TCP/UDP flow for port ", lport, " created");
  m_filters[lport] = f;
  return Status::Ok;
}

void
Device::unlisten(UNUSED const stack::ipv4::Protocol proto, const uint16_t lport,
                 UNUSED stack::ipv4::Address const& raddr,
                 UNUSED const uint16_t rport)
{
  if (m_filters.count(lport) > 0) {
    ibv_destroy_flow(m_filters[lport]);
    m_filters.erase(lport);
  }
}

/*
 * NOTE It is tempting to use a do/while loop here, but the idea is flawed. The
 * parent event loop needs some breathing room to do other things in case of
 * bursts.
 */
Status
Device::poll(Processor& proc)
{
  int cqn = 0;
  struct ibv_wc wc[m_nbuf];
  /*
   * Process the incoming recv buffers.
   */
  cqn = ibv_poll_cq(m_recvcq, m_nbuf, wc);
  if (cqn < 0) {
    m_log.error("OFED", "polling recv completion queue failed");
    return Status::HardwareError;
  }
  if (cqn == 0) {
    return Status::NoDataAvailable;
  }
  m_log.debug("OFED", cqn, " buffers available");
  /*
   * Process the buffers.
   */
  int pre = 0;
  m_pending = cqn;
  for (int i = 0; i < cqn; i += 1) {
    int id = wc[i].wr_id;
    size_t len = wc[i].byte_len;
    const uint8_t* addr = m_recvbuf + size_t(id) * RECV_BUFLEN;
    m_log.trace("OFED", "processing id=", id, " addr=", (void*)addr,
                " len=", len);
    /*
     * Validate the IP checksums
     */
#ifdef TULIPS_HAS_HW_CHECKSUM
    if (wc[i].wc_flags & IBV_FLOW_SPEC_IPV4) {
      if (m_hints & Device::VALIDATE_IP_CSUM) {
        if (!(wc[i].wc_flags & IBV_WC_IP_CSUM_OK)) {
          m_log.error("OFED", "invalid IP checksum, dropping packet");
          continue;
        }
      }
    }
    if (wc[i].wc_flags & IBV_FLOW_SPEC_TCP) {
      if (m_hints & Device::VALIDATE_L4_CSUM) {
        if (!(wc[i].wc_flags & IBV_WC_IP_CSUM_OK)) {
          m_log.error("OFED", "invalid TCP/UDP checksum, dropping packet");
          continue;
        }
      }
    }
#endif
    /*
     * Process the packet.
     */
    proc.process(len, addr, system::Clock::read());
    /*
     * Re-post the buffers every 10 WCs.
     */
    if (i > 0 && i % POST_RECV_THRESHOLD == 0) {
      for (int j = pre; j < pre + POST_RECV_THRESHOLD; j += 1) {
        const int lid = wc[j].wr_id;
        Status res = postReceive(lid);
        if (res != Status::Ok) {
          m_log.error("OFED", "re-post receive of buffer id=", lid, "failed");
          return Status::HardwareError;
        }
      }
      pre += POST_RECV_THRESHOLD;
      m_pending -= POST_RECV_THRESHOLD;
    }
  }
  /*
   * Prepare the received buffers for repost.
   */
  for (int i = pre; i < cqn; i += 1) {
    const int id = wc[i].wr_id;
    Status res = postReceive(id);
    if (res != Status::Ok) {
      m_log.error("OFED", "re-post receive of buffer id=", id, "failed");
      return Status::HardwareError;
    }
  }
  m_pending = 0;
  return Status::Ok;
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  sigset_t sigset;
  struct pollfd pfd = { m_comp->fd, POLLIN, 0 };
  struct timespec tsp = { 0, long(ns) };
  /*
   * Prepare the signal set.
   */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGALRM);
  sigaddset(&sigset, SIGINT);
  /*
   * Check if we need to clean the events.
   */
  if (m_events == EVENT_CLEANUP_THRESHOLD) {
    ibv_ack_cq_events(m_recvcq, m_events);
    m_events = 0;
  }
  /*
   * Request a notification.
   */
  if (ibv_req_notify_cq(m_recvcq, 0) != 0) {
    m_log.error("OFED", "requesting notification failed");
    return Status::HardwareError;
  }
  /*
   * Wait for the notification.
   */
  int rc = ::ppoll(&pfd, 1, &tsp, &sigset);
  /*
   * In case of an error (and not an interruption).
   */
  if (rc < 0 && errno != EINTR) {
    return Status::HardwareError;
  }
  /*
   * In case of a timeout.
   */
  else if (rc == 0) {
    return Status::NoDataAvailable;
  }
  /*
   * Get the notification if there is any pending event.
   */
  else if (rc > 0) {
    ibv_cq* cq = nullptr;
    void* context = nullptr;
    if (ibv_get_cq_event(m_comp, &cq, &context) != 0) {
      m_log.error("OFED", "getting notification failed");
      return Status::HardwareError;
    }
    m_events += 1;
  }
  /*
   * Poll the CQ if there is an event on the CQ or we have been interrupted.
   */
  return poll(proc);
}

Status
Device::prepare(uint8_t*& buf)
{
  int cqn;
  struct ibv_wc wc[m_nbuf];
  /*
   * Process the successfully sent buffers.
   */
  cqn = ibv_poll_cq(m_sendcq, m_nbuf, wc);
  if (cqn < 0) {
    m_log.error("OFED", "polling send completion queue failed");
    return Status::HardwareError;
  }
  /*
   * Queue the sent buffers.
   */
  for (int i = 0; i < cqn; i += 1) {
    auto* addr = (uint8_t*)wc[i].wr_id; // NOLINT
    tulips_fifo_push(m_sent, &addr);
  }
  /*
   * Look for an available buffer.
   */
  if (tulips_fifo_empty(m_free) == TULIPS_FIFO_YES) {
    buf = nullptr;
    return Status::NoMoreResources;
  }
  if (tulips_fifo_front(m_free, (void**)&buf) != TULIPS_FIFO_OK) {
    return Status::HardwareError;
  }
  m_log.trace("OFED", "preparing buffer ", (void*)buf);
  tulips_fifo_pop(m_free);
  return Status::Ok;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  /*
   * Get the header length.
   */
#ifdef TULIPS_HAS_HW_TSO
  uint32_t header_len;
  if (!stack::utils::headerLength(buf, len, header_len)) {
    m_log.error("OFED", "cannot get packet header length");
    return Status::IncompleteData;
  }
  /*
   * Reject the request if the MSS provided is too small for the job.
   */
  if (len > (m_hwmtu + stack::ethernet::HEADER_LEN) && mss <= header_len) {
    m_log.error("OFED", "mss=", mss, " for hwmtu=", m_hwmtu, " and len=", len);
    return Status::InvalidArgument;
  }
  /*
   * Adjust the MSS if the MSS provided is 0 or too big for the device.
   */
  uint16_t lmss = mss;
  if (mss == 0 || mss > m_hwmtu - header_len) {
    lmss = m_hwmtu + stack::ethernet::HEADER_LEN - header_len;
    m_log.debug("OFED", "adjusting request MSS from " << mss << " to " << lmss);
  }
#endif
  /*
   * Prepare the SGE.
   */
  struct ibv_sge sge;
#ifdef TULIPS_HAS_HW_TSO
  if (len > header_len) {
    sge.addr = (uint64_t)buf + header_len;
    sge.length = len - header_len;
    sge.lkey = m_sendmr->lkey;
  } else {
    sge.addr = (uint64_t)buf;
    sge.length = len;
    sge.lkey = m_sendmr->lkey;
  }
#else
  sge.addr = (uint64_t)buf;
  sge.length = len;
  sge.lkey = m_sendmr->lkey;
#endif
  /*
   * Prepare the WR.
   */
  struct ibv_send_wr wr;
  memset(&wr, 0, sizeof(wr));
  wr.wr_id = (uint64_t)buf;
  wr.sg_list = &sge;
  wr.num_sge = 1;
#ifdef TULIPS_HAS_HW_TSO
  if (len > header_len) {
    wr.tso.mss = lmss;
    wr.tso.hdr = buf;
    wr.tso.hdr_sz = header_len;
    wr.opcode = IBV_WR_TSO;
  } else {
    wr.opcode = IBV_WR_SEND;
  }
#else
  wr.opcode = IBV_WR_SEND;
#endif
  wr.send_flags = IBV_SEND_SIGNALED | IBV_SEND_IP_CSUM;
  /*
   * Mark the transaction inline.
   */
  wr.send_flags |= len <= INLINE_DATA_THRESHOLD ? IBV_SEND_INLINE : 0;
  /*
   * Post the work request.
   */
  struct ibv_send_wr* bad_wr;
  if (ibv_post_send(m_qp, &wr, &bad_wr) != 0) {
    m_log.error("OFED", "post send of buffer len=", len, " failed, ",
                strerror(errno));
    return Status::HardwareError;
  }
  m_log.trace("OFED", "committing buffer ", (void*)buf, " len ", len);
  return Status::Ok;
}

Status
Device::release(uint8_t* const buf)
{
  size_t count = tulips_fifo_length(m_sent);
  /*
   * Scan the sent buffer FIFO.
   */
  for (size_t i = 0; i < count; i += 1) {
    uint8_t* buffer = nullptr;
    /*
     * Get the front of the FIFO..
     */
    if (tulips_fifo_front(m_sent, (void**)&buffer) != TULIPS_FIFO_OK) {
      return Status::HardwareError;
    }
    /*
     * Pop the FIFO.
     */
    tulips_fifo_pop(m_free);
    /*
     * Bail out if the buffers are equal.
     */
    if (buffer == buf) {
      tulips_fifo_push(m_free, buffer);
      return Status::Ok;
    }
    /*
     * Push back the buffer otherwise.
     */
    tulips_fifo_push(m_sent, buffer);
  }
  /*
   * Done.
   */
  return Status::InvalidArgument;
}

}
