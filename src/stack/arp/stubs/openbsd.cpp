#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Utils.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

namespace tulips::stack::arp::stub {

static bool
getinetaddr(system::Logger& log, std::string_view host, struct in_addr* inap)
{
  struct hostent* hp;
  auto shost = std::string(host);
  /*
   * Loop-up the host address.
   */
  if (inet_aton(shost.c_str(), inap) == 1) {
    log.debug("ARP", "inet_aton for " << host << " succeeded");
    return true;
  }
  if ((hp = gethostbyname(shost.c_str())) == nullptr) {
    log.debug("ARP", "gethostbyname for " << host << " failed");
    return false;
  }
  /*
   * Copy the result.
   */
  memcpy(inap, hp->h_addr, sizeof(*inap));
  return true;
}

static bool
search(in_addr_t const& addr, ethernet::Address& lladdr)
{
  int mib[7];
  size_t needed;
  char *lim, *buf = nullptr, *next;
  struct rt_msghdr* rtm;
  struct sockaddr_inarp* sin;
  struct sockaddr_dl* sdl;
  bool result = false;
  /*
   * Setup MIB parameters.
   */
  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = RTF_LLINFO;
  mib[6] = getrtable();
  /*
   * Fetch the table entries.
   */
  while (1) {
    if (sysctl(mib, 7, nullptr, &needed, nullptr, 0) == -1) {
      LOG("ARP", "route-sysctl-estimate");
    }
    if (needed == 0) {
      log.debug("ARP", "sysctl failed");
      return false;
    }
    if ((buf = (char*)realloc(buf, needed)) == nullptr) {
      LOG("ARP", "malloc");
    }
    if (sysctl(mib, 7, buf, &needed, nullptr, 0) == -1) {
      log.debug("ARP", strerror(errno));
      if (errno == ENOMEM) {
        continue;
      }
      LOG("ARP", "actual retrieval of routing table");
    }
    lim = buf + needed;
    break;
  }
  log.debug("ARP", "found: " << needed);
  /*
   * Search for a match.
   */
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr*)next;
    if (rtm->rtm_version != RTM_VERSION) {
      continue;
    }
    sin = (struct sockaddr_inarp*)(next + rtm->rtm_hdrlen);
    sdl = (struct sockaddr_dl*)(sin + 1);
    if (addr != sin->sin_addr.s_addr) {
      log.debug("ARP", "skipping " << inet_ntoa(sin->sin_addr));
      continue;
    }
    u_char* cp = (u_char*)LLADDR(sdl);
    lladdr = ethernet::Address(cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
    result = true;
    break;
  }
  /*
   * Clean-up.
   */
  free(buf);
  return result;
}

static bool
get(system::Logger& log, std::string_view host, ethernet::Address& addr)
{
  struct sockaddr_inarp sin = { sizeof(sin), AF_INET, 0, { 0 }, { 0 }, 0, 0 };
  return getinetaddr(log, host, &sin.sin_addr) &&
         search(sin.sin_addr.s_addr, addr);
}

bool
lookup(system::Logger& log, std::string_view eth, ipv4::Address const& ip,
       ethernet::Address& hw)
{
  return get(log, ip.toString(), hw);
}

}
