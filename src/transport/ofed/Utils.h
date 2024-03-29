#pragma once

#include <tulips/transport/ofed/Device.h>
#include <string>

#define PRINT_EXP_CAP(__flags, __cap)                                          \
  m_log.debug("OFED", #__cap, " = ", std::boolalpha,                           \
              (bool)(((__flags).device_cap_flags_ex & (__cap)) == (__cap)))

#define PRINT_WC_FLAG(__wc, __flag)                                            \
  m_log.debug("OFED", #__flag, " = ", std::boolalpha,                          \
              (bool)(((__wc).exp_wc_flags & (__flag)) == (__flag)))

#define HAS_TSO(__caps)                                                        \
  ((__caps).max_tso > 0 && ((__caps).supported_qpts | IBV_QPT_RAW_PACKET))

bool getInterfaceDeviceAndPortIds(std::string_view ifn, std::string& name,
                                  int& portid);

bool isSupportedDevice(std::string_view ifn);

bool findSupportedInterface(std::string& ifn);

void setup(ibv_context* context, ibv_pd* pd, const uint8_t port,
           const uint16_t nbuf, const size_t sndlen, const size_t rcvlen,
           ibv_comp_channel*& comp, ibv_cq*& sendcq, ibv_cq*& recvcq,
           ibv_qp*& qp, uint8_t*& sendbuf, uint8_t*& recvbuf, ibv_mr*& sendmr,
           ibv_mr*& recvmr);
