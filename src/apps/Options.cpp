#include "tulips/system/Logger.h"
#include <tulips/apps/Options.h>
#include <cstdint>

namespace tulips::apps {

using system::Logger;

Options::Options(TCLAP::CmdLine& cmd)
  : usd("u", "us", "uS delay between sends", false, 1000, "DELAY", cmd)
  , nag("N", "nodelay", "Disable Nagle's algorithm", cmd)
  , snd("s", "sender", "Sender mode", cmd)
  , lla("L", "lladdr", "Link address", true, "", "LLADDR", cmd)
  , src("S", "source", "Local IPv4 address", true, "", "IPv4", cmd)
  , rte("R", "route", "Default route", true, "", "IPv4", cmd)
  , msk("M", "netmask", "Local netmask", false, "255.255.255.0", "IPv4", cmd)
  , dst("D", "destination", "Remote IPv4 address", false, "", "IPv4", cmd)
  , pcp("P", "pcap", "Dump packets", cmd)
  , dly("i", "interval", "Statistics interval", false, 10, "INTERVAL", cmd)
  , iff("I", "interface", "Network interface", false, "", "INTERFACE", cmd)
  , prt("p", "port", "Port to listen/connect to", false, "PORT", cmd)
  , con("n", "nconn", "Server connections", false, 16, "NCONNS", cmd)
  , wai("w", "wait", "Wait instead of poll", cmd)
  , len("l", "length", "Payload length", false, 8, "LEN", cmd)
  , cnt("c", "count", "Send count", false, 0, "COUNT", cmd)
  , cpu("a", "affinity", "CPU affinity", false, -1, "CPUID", cmd)
  , vrb("v", "verbose", "Verbosity", false, Logger::Level::Info, "LEVEL", cmd)
  , ssl("", "ssl", "Use OpenSSL", cmd)
  , crt("", "cert", "SSL certificate", false, "", "PEM", cmd)
  , key("", "key", "SSL private key", false, "", "PEM", cmd)
{}

bool
Options::isSane() const
{
  if (snd.isSet() && !dst.isSet()) {
    std::cerr << "Remote IPv4 address must be set" << std::endl;
    return false;
  }
  if (prt.getValue().empty()) {
    std::cerr << "Port list cannot be empty" << std::endl;
    return false;
  }
  return true;
}

}
