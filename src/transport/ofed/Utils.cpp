#include "Utils.h"
#include <tulips/system/Logger.h>
#include <tulips/system/Utils.h>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static bool
getInterfaceDriverName(std::string_view ifn, std::string& drv)
{
  char path[PATH_MAX], target[PATH_MAX];
  memset(path, 0, PATH_MAX);
  memset(target, 0, PATH_MAX);
  sprintf(path, "/sys/class/net/%.*s/device/driver", (int)ifn.length(),
          ifn.data());
  if (readlink(path, target, PATH_MAX) < 0) {
    return false;
  }
  std::vector<std::string> parts;
  tulips::system::utils::split(std::string(target), '/', parts);
  drv = *parts.rbegin();
  return true;
}

static int
filterInfinibandEntry(const struct dirent* d)
{
  std::string e(d->d_name);
  return e != "." && e != "..";
}

bool
getInterfaceDeviceAndPortIds(std::string_view ifn, std::string& name,
                             int& portid)
{
  std::ifstream ifs;
  char path[PATH_MAX];
  memset(path, 0, PATH_MAX);
  /*
   * Get the device name.
   */
  struct dirent** entries;
  sprintf(path, "/sys/class/net/%.*s/device/infiniband", (int)ifn.length(),
          ifn.data());
  if (scandir(path, &entries, filterInfinibandEntry, ::alphasort) != 1) {
    return false;
  }
  name = std::string(entries[0]->d_name);
  free(entries[0]);
  free(entries);
  /*
   * Get the port ID.
   */
  sprintf(path, "/sys/class/net/%.*s/dev_port", (int)ifn.length(), ifn.data());
  ifs.open(path);
  if (!ifs.good()) {
    return false;
  }
  ifs >> portid;
  ifs.close();
  return true;
}

bool
isSupportedDevice(std::string_view ifn)
{
  std::string drvname;
  if (!getInterfaceDriverName(ifn, drvname)) {
    return false;
  }
  return drvname == "mlx4_core" || drvname == "mlx5_core";
}

static int
supportedDeviceFilter(const struct dirent* d)
{
  std::string ifn(d->d_name);
  if (ifn == "." || ifn == ".." || ifn == "lo") {
    return 0;
  }
  return isSupportedDevice(ifn) ? 1 : 0;
}

bool
findSupportedInterface(std::string& ifn)
{
  struct dirent** sel;
  int count =
    scandir("/sys/class/net", &sel, supportedDeviceFilter, ::alphasort);
  /*
   * Check if any entry is valid.
   */
  if (count <= 0) {
    return false;
  }
  /*
   * Grab the first available entry.
   */
  ifn = std::string(sel[0]->d_name);
  /*
   * Clean-up.
   */
  for (int i = 0; i < count; i += 1) {
    free(sel[i]);
  }
  free(sel);
  return true;
}

void
setup(ibv_context* context, ibv_pd* pd, const uint8_t port, const uint16_t nbuf,
      const size_t sndlen, const size_t rcvlen, ibv_comp_channel*& comp,
      ibv_cq*& sendcq, ibv_cq*& recvcq, ibv_qp*& qp, uint8_t*& sendbuf,
      uint8_t*& recvbuf, ibv_mr*& sendmr, ibv_mr*& recvmr)
{
  /*
   * Create a completion channel for the receive CQ.
   */
  comp = ibv_create_comp_channel(context);
  if (comp == nullptr) {
    throw std::runtime_error("Cannot create receive completion channel");
  }
  /*
   * Create a send completion queue.
   */
  struct ibv_cq_init_attr_ex send_cq_attr = {
    .cqe = nbuf,
    .comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS,
    .flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP,
  };
  sendcq = ibv_cq_ex_to_cq(ibv_create_cq_ex(context, &send_cq_attr));
  if (sendcq == nullptr) {
    throw std::runtime_error("Cannot create send completion queue");
  }
  /*
   * Create a recv completion queue.
   */
  struct ibv_cq_init_attr_ex recv_cq_attr = {
    .cqe = nbuf,
    .channel = comp,
    .comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS,
    .flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP,
  };
  recvcq = ibv_cq_ex_to_cq(ibv_create_cq_ex(context, &recv_cq_attr));
  if (recvcq == nullptr) {
    throw std::runtime_error("Cannot create receive completion queue");
  }
  /*
   * Change the blocking mode of the completion channel
   */
  int flags = fcntl(comp->fd, F_GETFL);
  if (fcntl(comp->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    throw std::runtime_error("Cannot make the completion channel async");
  }
  /*
   * Setup the QP attributes.
   */
  struct ibv_qp_init_attr_ex qp_init_attr;
  qp_init_attr.comp_mask = IBV_QP_INIT_ATTR_PD;
  qp_init_attr.qp_context = nullptr;
  qp_init_attr.send_cq = sendcq;
  qp_init_attr.recv_cq = recvcq;
  qp_init_attr.srq = nullptr;
  qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
  qp_init_attr.sq_sig_all = 0;
  qp_init_attr.pd = pd;
  /*
   * Setup the TSO header
   */
#ifdef TULIPS_HAS_HW_TSO
  qp_init_attr.comp_mask |= IBV_QP_INIT_ATTR_MAX_TSO_HEADER;
  qp_init_attr.max_tso_header = 58;
#endif
  /*
   * Setup the QP capavbilities (this should be taken from the device).
   */
  qp_init_attr.cap.max_send_wr = nbuf;
  qp_init_attr.cap.max_recv_wr = nbuf;
  qp_init_attr.cap.max_send_sge = 1;
  qp_init_attr.cap.max_recv_sge = 1;
  qp_init_attr.cap.max_inline_data =
    tulips::transport::ofed::Device::INLINE_DATA_THRESHOLD;
  /*
   * Create the queue pair.
   */
  qp = ibv_create_qp_ex(context, &qp_init_attr);
  if (qp == nullptr) {
    throw std::runtime_error("Cannot create queue pair");
  }
  /*
   * Initialize the QP with its ports.
   */
  int qp_flags = 0;
  struct ibv_qp_attr qp_attr;
  memset(&qp_attr, 0, sizeof(qp_attr));
  qp_flags = IBV_QP_STATE | IBV_QP_PORT;
  qp_attr.qp_state = IBV_QPS_INIT;
  qp_attr.port_num = port + 1;
  if (ibv_modify_qp(qp, &qp_attr, qp_flags) != 0) {
    throw std::runtime_error("Cannot switch QP to INIT state");
  }
  /*
   * Move to ready to receive.
   */
  memset(&qp_attr, 0, sizeof(qp_attr));
  qp_flags = IBV_QP_STATE;
  qp_attr.qp_state = IBV_QPS_RTR;
  if (ibv_modify_qp(qp, &qp_attr, qp_flags) != 0) {
    throw std::runtime_error("Cannot switch QP to RTR state");
  }
  /*
   * Move to ready to send.
   */
  memset(&qp_attr, 0, sizeof(qp_attr));
  qp_flags = IBV_QP_STATE;
  qp_attr.qp_state = IBV_QPS_RTS;
  if (ibv_modify_qp(qp, &qp_attr, qp_flags) != 0) {
    throw std::runtime_error("Cannot switch QP to RTS state");
  }
  /*
   * Create and register send buffers.
   */
  sendbuf = (uint8_t*)mmap(nullptr, nbuf * sndlen, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
  if (sendbuf == nullptr) {
    throw std::runtime_error("Cannot MMAP() buffer");
  }
  sendmr = ibv_reg_mr(pd, sendbuf, nbuf * sndlen, IBV_ACCESS_LOCAL_WRITE);
  if (sendmr == nullptr) {
    throw std::runtime_error("Cannot create a memory region");
  }
  /*
   * Create and register receive buffers.
   */
  recvbuf = (uint8_t*)mmap(nullptr, nbuf * rcvlen, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
  if (recvbuf == nullptr) {
    throw std::runtime_error("Cannot MMAP() buffer");
  }
  recvmr = ibv_reg_mr(pd, recvbuf, nbuf * rcvlen, IBV_ACCESS_LOCAL_WRITE);
  if (recvmr == nullptr) {
    throw std::runtime_error("Cannot create a memory region");
  }
}
