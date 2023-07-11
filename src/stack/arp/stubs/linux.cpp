#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Utils.h>
#include <cerrno>
#include <cstring>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define ARP_VERBOSE 1

#if ARP_VERBOSE
#define ARP_LOG(__args) LOG("ARP", __args)
#else
#define ARP_LOG(...) ((void)0)
#endif

namespace tulips::stack::arp::stub {

static bool
send_dummy(const int sock, ipv4::Address const& ip)
{
  struct sockaddr_in servaddr;
  memset((char*)&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(12345);
  memcpy((void*)&servaddr.sin_addr, ip.data(), 4);
  ARP_LOG("sending dummy data to " << ip.toString());
  if (sendto(sock, nullptr, 0, 0, (struct sockaddr*)&servaddr,
             sizeof(servaddr)) < 0) {
    close(sock);
    LOG("ARP", "cannot send dummy data: " << strerror(errno));
    return false;
  }
  return true;
}

static bool
read_address(const int sock, std::string const& eth, ipv4::Address const& ip,
             ethernet::Address& hw)
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
  strncpy(areq.arp_dev, eth.c_str(), 15);
  /*
   * Run the ARP request.
   */
  ARP_LOG("reading kernel ARP entry");
  if (ioctl(sock, SIOCGARP, (caddr_t)&areq) == -1) {
    LOG("ARP", "SIOCGARP: " << strerror(errno));
    return false;
  }
  memcpy(hw.data(), areq.arp_ha.sa_data, ETHER_ADDR_LEN);
  return hw != tulips::stack::ethernet::Address();
}

bool
lookup(std::string const& eth, tulips::stack::ipv4::Address const& ip,
       tulips::stack::ethernet::Address& hw)
{
  /*
   * Create a dummy socket.
   */
  ARP_LOG("creating datagram socket");
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    LOG("ARP", "cannot create datagram socket: " << strerror(errno));
    return false;
  }
  /*
   * Send some dummy data over.
   */
  if (read_address(sock, eth, ip, hw)) {
    LOG("ARP", "got " << hw.toString() << " for " << ip.toString());
    close(sock);
    return true;
  }
  ARP_LOG("ARP entry missing for " << ip.toString());
  /*
   * Wait one millisecond for the ARP request to complete.
   */
  send_dummy(sock, ip);
  usleep(1000);
  /*
   * Try to read the address again.
   */
  bool ret = read_address(sock, eth, ip, hw);
  LOG("ARP", "got " << hw.toString() << " for " << ip.toString());
  close(sock);
  return ret;
}

}
