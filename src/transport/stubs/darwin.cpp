#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/Utils.h>
#include <cerrno>
#include <string>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>

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
getInterfaceInformation(system::Logger& log, std::string_view ifn,
                        stack::ethernet::Address& hwaddr, uint32_t& mtu)
{
  auto sifn = std::string(ifn);
  /*
   * Check that the interface name is valid.
   */
  if (ifn.length() > IFNAMSIZ) {
    return false;
  }
  /*
   * Get the ethernet address.
   */
  struct ifaddrs *ifap, *ifaptr;
  uint8_t* ptr;
  if (getifaddrs(&ifap) == 0) {
    for (ifaptr = ifap; ifaptr != nullptr; ifaptr = (ifaptr)->ifa_next) {
      if (!strcmp((ifaptr)->ifa_name, sifn.c_str()) &&
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
    log.error("TRANS", strerror(errno));
    return false;
  }
  /*
   * Get the device MTU.
   */
  struct ifreq ifreq = {};
  memcpy(ifreq.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFMTU, &ifreq) < 0) {
    log.error("TRANS", strerror(errno));
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
                        UNUSED stack::ethernet::Address& hwaddr,
                        UNUSED uint32_t& mtu, stack::ipv4::Address& ipaddr,
                        stack::ipv4::Address& draddr,
                        stack::ipv4::Address& ntmask)
{
  /*
   * Check that the interface name is valid.
   */
  if (ifn.length() > IFNAMSIZ) {
    return false;
  }
  /*
   * Create a dummy socket.
   */
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0) {
    log.error("TRANS", strerror(errno));
    return false;
  }
  /*
   * Get the IPv4 address.
   */
  struct ifreq ifreq = {};
  memcpy(ifreq.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFADDR, &ifreq) < 0) {
    log.error("TRANS", strerror(errno));
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
  memcpy(ifreq.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFNETMASK, &ifreq) < 0) {
    log.error("TRANS", strerror(errno));
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
