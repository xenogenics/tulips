#include <tulips/system/Utils.h>
#include <tulips/transport/Utils.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

namespace {

static bool
getDefaultRoute(system::Logger& log, tulips::stack::ipv4::Address const& ip,
                tulips::stack::ipv4::Address& dr)
{
  int mib[7];
  size_t needed;
  char *lim, *buf = nullptr, *next;
  struct rt_msghdr* rtm;
  struct sockaddr_in *sin, *adr;
  bool result = false;
  /*
   * Setup MIB parameters.
   */
  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = RTF_GATEWAY;
  mib[6] = getrtable();
  /*
   * Fetch the table entries.
   */
  while (1) {
    if (sysctl(mib, 7, nullptr, &needed, nullptr, 0) == -1) {
      LOG("ARP", "route-sysctl-estimate");
    }
    if (needed == 0) {
      log.debug("TRANS", "sysctl failed");
      return false;
    }
    if ((buf = (char*)realloc(buf, needed)) == nullptr) {
      LOG("ARP", "malloc");
    }
    if (sysctl(mib, 7, buf, &needed, nullptr, 0) == -1) {
      log.debug("TRANS", strerror(errno));
      if (errno == ENOMEM) {
        continue;
      }
    }
    lim = buf + needed;
    break;
  }
  log.debug("TRANS", "found: ", needed);
  /*
   * Search for a match.
   */
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr*)next;
    if (rtm->rtm_version != RTM_VERSION) {
      continue;
    }
    sin = (struct sockaddr_in*)(next + rtm->rtm_hdrlen);
    adr = sin + 1;
    memcpy(dr.data(), &adr->sin_addr.s_addr, 4);
    result = true;
    break;
  }
  /*
   * Clean-up.
   */
  free(buf);
  return result;
}

}

namespace tulips::transport::utils {

bool
getInterfaceInformation(system::Logger& log, std::string_view ifn,
                        stack::ethernet::Address& hwaddr, uint32_t& mtu)
{
  /*
   * Get the ethernet address.
   */
  struct ifaddrs *ifap, *ifaptr;
  uint8_t* ptr;
  if (getifaddrs(&ifap) == 0) {
    for (ifaptr = ifap; ifaptr != nullptr; ifaptr = (ifaptr)->ifa_next) {
      if (!strcmp((ifaptr)->ifa_name, ifn.c_str()) &&
          (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
        ptr = (uint8_t*)LLADDR((struct sockaddr_dl*)(ifaptr)->ifa_addr);
        hwaddr = stack::ethernet::Address(ptr[0], ptr[1], ptr[2], ptr[3],
                                          ptr[4], ptr[5]);
        break;
      }
    }
    freeifaddrs(ifap);
  } else {
    return false;
  }
  /*
   * Create a dummy socket.
   */
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0) {
    log.debug("TRANS", strerror(errno));
    return false;
  }
  /*
   * Get the device MTU.
   */
  struct ifreq ifreq;
  memcpy(ifreq.ifr_name, ifn.c_str(), IFNAMSIZ);
  if (ioctl(sock, SIOCGIFMTU, &ifreq) < 0) {
    log.debug("TRANS", strerror(errno));
    close(sock);
    return false;
  }
  mtu = ifreq.ifr_ifru.ifru_metric;
  /*
   * Clean-up.
   */
  close(sock);
  return true;
}

bool
getInterfaceInformation(system::Logger& log, std::string_view ifn,
                        stack::ipv4::Address& ipaddr,
                        stack::ipv4::Address& draddr,
                        stack::ipv4::Address& ntmask)
{
  /*
   * Create a dummy socket.
   */
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0) {
    log.debug("TRANS", strerror(errno));
    return false;
  }
  /*
   * Get the IPv4 address.
   */
  struct ifreq ifreq;
  memcpy(ifreq.ifr_name, ifn.c_str(), IFNAMSIZ);
  if (ioctl(sock, SIOCGIFADDR, &ifreq) < 0) {
    log.debug("TRANS", strerror(errno));
    close(sock);
    return false;
  }
  memcpy(ipaddr.data(), &ifreq.ifr_ifru.ifru_addr.sa_data[2], 4);
  /*
   * Get the IPv4 default route address.
   */
  if (!getDefaultRoute(log, ipaddr, draddr)) {
    return false;
  }
  /*
   * Get the IPv4 netmask.
   */
  memcpy(ifreq.ifr_name, ifn.c_str(), IFNAMSIZ);
  if (ioctl(sock, SIOCGIFNETMASK, &ifreq) < 0) {
    log.debug("TRANS", strerror(errno));
    close(sock);
    return false;
  }
  memcpy(ntmask.data(), &ifreq.ifr_ifru.ifru_addr.sa_data[2], 4);
  /*
   * Clean-up.
   */
  return true;
}

}
