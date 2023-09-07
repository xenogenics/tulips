#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Utils.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>

namespace tulips::stack::arp::stub {

static bool
send_dummy(system::Logger& log, const int sock, ipv4::Address const& ip)
{
  struct sockaddr_in servaddr;
  memset((char*)&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(12345);
  memcpy((void*)&servaddr.sin_addr, ip.data(), 4);
  log.debug("ARP", "sending dummy data to ", ip.toString());
  if (sendto(sock, nullptr, 0, 0, (struct sockaddr*)&servaddr,
             sizeof(servaddr)) < 0) {
    close(sock);
    log.error("ARP", "cannot send dummy data: ", strerror(errno));
    return false;
  }
  return true;
}

static bool
read_address(system::Logger& log, const int sock, std::string_view eth,
             ipv4::Address const& ip, ethernet::Address& hw)
{
  struct arpreq areq;
  struct sockaddr_in* sin;
  /*
   * Build the ARP request.
   */
  memset(&areq, 0, sizeof(areq));
  sin = (struct sockaddr_in*)&areq.arp_pa;
  sin->sin_family = AF_INET;
  memcpy(&sin->sin_addr, ip.data(), 4);
  sin = (struct sockaddr_in*)&areq.arp_ha;
  sin->sin_family = ARPHRD_ETHER;
  strncpy(areq.arp_dev, eth.data(), 15);
  /*
   * Run the ARP request.
   */
  log.debug("ARP", "reading kernel ARP entry");
  if (ioctl(sock, SIOCGARP, (caddr_t)&areq) == -1) {
    log.error("ARP", "SIOCGARP: ", strerror(errno));
    return false;
  }
  memcpy(hw.data(), areq.arp_ha.sa_data, ETHER_ADDR_LEN);
  return hw != tulips::stack::ethernet::Address();
}

bool
lookup(system::Logger& log, std::string_view eth,
       tulips::stack::ipv4::Address const& ip,
       tulips::stack::ethernet::Address& hw)
{
  /*
   * Create a dummy socket.
   */
  log.debug("ARP", "creating datagram socket");
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    log.error("ARP", "cannot create datagram socket: ", strerror(errno));
    return false;
  }
  /*
   * Send some dummy data over.
   */
  if (read_address(log, sock, eth, ip, hw)) {
    log.debug("ARP", "got ", hw.toString(), " for ", ip.toString());
    close(sock);
    return true;
  }
  log.debug("ARP", "ARP entry missing for ", ip.toString());
  /*
   * Wait one millisecond for the ARP request to complete.
   */
  send_dummy(log, sock, ip);
  usleep(1000);
  /*
   * Try to read the address again.
   */
  bool ret = read_address(log, sock, eth, ip, hw);
  log.debug("ARP", "got ", hw.toString(), " for ", ip.toString());
  close(sock);
  return ret;
}

}
