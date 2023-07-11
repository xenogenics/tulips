#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/Utils.h>
#include <cerrno>
#include <string>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/types.h>

#define TRANS_VERBOSE 1

#if TRANS_VERBOSE
#define TRANS_LOG(__args) LOG("TRANS", __args)
#else
#define TRANS_LOG(...) ((void)0)
#endif

namespace {

bool
getDefaultRoute(UNUSED tulips::stack::ipv4::Address const& ip,
                UNUSED tulips::stack::ipv4::Address& dr)
{
  return false;
}

}

namespace tulips::transport::utils {

bool
getInterfaceInformation(std::string const& ifn,
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
    TRANS_LOG(strerror(errno));
    return false;
  }
  /*
   * Get the device MTU.
   */
  struct ifreq ifreq = {};
  memcpy(ifreq.ifr_name, ifn.c_str(), IFNAMSIZ);
  if (ioctl(sock, SIOCGIFMTU, &ifreq) < 0) {
    TRANS_LOG(strerror(errno));
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
getInterfaceInformation(std::string const& ifn,
                        UNUSED stack::ethernet::Address& hwaddr,
                        UNUSED uint32_t& mtu, stack::ipv4::Address& ipaddr,
                        stack::ipv4::Address& draddr,
                        stack::ipv4::Address& ntmask)
{
  /*
   * Create a dummy socket.
   */
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0) {
    TRANS_LOG(strerror(errno));
    return false;
  }
  /*
   * Get the IPv4 address.
   */
  struct ifreq ifreq = {};
  memcpy(ifreq.ifr_name, ifn.c_str(), IFNAMSIZ);
  if (ioctl(sock, SIOCGIFADDR, &ifreq) < 0) {
    TRANS_LOG(strerror(errno));
    close(sock);
    return false;
  }
  memcpy(ipaddr.data(), &ifreq.ifr_ifru.ifru_addr.sa_data[2], 4);
  /*
   * Get the IPv4 default route address.
   */
  if (!getDefaultRoute(ipaddr, draddr)) {
    return false;
  }
  /*
   * Get the IPv4 netmask.
   */
  memcpy(ifreq.ifr_name, ifn.c_str(), IFNAMSIZ);
  if (ioctl(sock, SIOCGIFNETMASK, &ifreq) < 0) {
    TRANS_LOG(strerror(errno));
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
