#pragma once

#include <cstdint>
#include <tclap/CmdLine.h>

namespace tulips::apps {

class Options
{
public:
  Options(TCLAP::CmdLine& cmd);

  bool isSane() const;

  int usDelay() const { return usd.getValue(); }
  bool noDelay() const { return nag.isSet(); }
  bool isSender() const { return snd.isSet(); }
  std::string_view linkAddress() const { return lla.getValue(); }
  std::string_view source() const { return src.getValue(); }
  std::string_view route() const { return rte.getValue(); }
  std::string_view mask() const { return msk.getValue(); }
  std::string_view destination() const { return dst.getValue(); }
  bool dumpPackets() const { return pcp.isSet(); }
  size_t interval() const { return dly.getValue(); }
  bool hasInterface() const { return iff.isSet(); }
  std::string interface() const { return iff.getValue(); }
  uint16_t port() const { return prt.getValue()[0]; }
  std::vector<uint16_t> ports() const { return prt.getValue(); }
  size_t connections() const { return con.getValue(); }
  bool wait() const { return wai.isSet(); }
  size_t length() const { return len.getValue(); }
  size_t count() const { return cnt.getValue(); }
  bool withSSL() const { return ssl.isSet(); }
  std::string_view sslCert() const { return crt.getValue(); }
  std::string_view sslKey() const { return key.getValue(); }
  long cpuId() const { return cpu.getValue(); }

private:
  TCLAP::ValueArg<int> usd;
  TCLAP::SwitchArg nag;
  TCLAP::SwitchArg snd;
  TCLAP::ValueArg<std::string> lla;
  TCLAP::ValueArg<std::string> src;
  TCLAP::ValueArg<std::string> rte;
  TCLAP::ValueArg<std::string> msk;
  TCLAP::ValueArg<std::string> dst;
  TCLAP::SwitchArg pcp;
  TCLAP::ValueArg<size_t> dly;
  TCLAP::ValueArg<std::string> iff;
  TCLAP::MultiArg<uint16_t> prt;
  TCLAP::ValueArg<size_t> con;
  TCLAP::SwitchArg wai;
  TCLAP::ValueArg<size_t> len;
  TCLAP::ValueArg<size_t> cnt;
  TCLAP::SwitchArg ssl;
  TCLAP::ValueArg<std::string> crt;
  TCLAP::ValueArg<std::string> key;
  TCLAP::ValueArg<long> cpu;
};

}
