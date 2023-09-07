#include <tulips/stack/Utils.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/Utils.h>
#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>

namespace {

bool
getGateway(tulips::system::Logger& log, std::string_view dev,
           tulips::stack::ipv4::Address& gw)
{
  std::ifstream route("/proc/net/route");
  int line_count = 0;
  /*
   * Check if the file is valid.
   */
  if (route.bad()) {
    log.error("TRANS", "cannot open /proc/net/route");
    return false;
  }
  /*
   * Look for the gateway matching the interface.
   */
  while (!route.eof()) {
    /*
     * Read a line from that file.
     */
    std::string line;
    std::vector<std::string> parts;
    std::getline(route, line);
    line_count += 1;
    /*
     * Skip the headers.
     */
    if (line_count <= 2) {
      continue;
    }
    /*
     * Parse the input.
     */
    tulips::system::utils::split(line, '\t', parts);
    if (parts[0] == dev) {
      union
      {
        std::array<uint8_t, 4> b;
        uint32_t a;
      };
      std::istringstream(parts[2]) >> std::hex >> a;
      gw = tulips::stack::ipv4::Address(b[0], b[1], b[2], b[3]);
      route.close();
      return true;
    }
  }
  route.close();
  return false;
}

}

namespace tulips::transport::utils {

bool
getInterfaceInformation(UNUSED system::Logger& log, std::string_view ifn,
                        stack::ethernet::Address& hwaddr, uint32_t& mtu)
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
    return false;
  }
  /*
   * Get the ethernet address.
   */
  struct ifreq req;
  memcpy(req.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
    close(sock);
    return false;
  }
  memcpy(hwaddr.data(), req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
  /*
   * Get the device MTU.
   */
  memcpy(req.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFMTU, &req) < 0) {
    close(sock);
    return false;
  }
  mtu = req.ifr_ifru.ifru_mtu;
  /*
   * Clean-up.
   */
  close(sock);
  return true;
}

bool
getInterfaceInformation(system::Logger& log, std::string_view ifn,
                        stack::ipv4::Address& ipaddr,
                        stack::ipv4::Address& ntmask,
                        stack::ipv4::Address& draddr)
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
    return false;
  }
  /*
   * Get the IPv4 address.
   */
  struct ifreq req;
  memcpy(req.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFADDR, &req) < 0) {
    close(sock);
    return false;
  }
  memcpy(ipaddr.data(), &req.ifr_addr.sa_data[2], 4);
  /*
   * Get the IPv4 netmask.
   */
  memcpy(req.ifr_name, ifn.data(), ifn.length());
  if (ioctl(sock, SIOCGIFNETMASK, &req) < 0) {
    close(sock);
    return false;
  }
  memcpy(ntmask.data(), &req.ifr_netmask.sa_data[2], 4);
  /*
   * Get the IPv4 gateway address.
   */
  if (!getGateway(log, ifn, draddr)) {
    close(sock);
    return false;
  }
  /*
   * Clean-up.
   */
  close(sock);
  return true;
}

}
