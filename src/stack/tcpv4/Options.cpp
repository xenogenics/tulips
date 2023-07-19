#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/stack/tcpv4/Options.h>
#include <tulips/system/Utils.h>
#include <cstdint>
#include <ostream>
#include <arpa/inet.h>

#define OPT_VERBOSE 1

#if OPT_VERBOSE
#define OPT_LOG(__args) LOG("TCP", __args)
#else
#define OPT_LOG(...) ((void)0)
#endif

namespace tulips::stack::tcpv4::Options {

void
parse(Connection& e, const uint16_t len, const uint8_t* const data)
{
  /*
   * Get the number of options bytes
   */
  const uint8_t* options = &data[HEADER_LEN];
  /*
   * Parse the options
   */
  for (int c = 0; c < len;) {
    uint8_t opt = options[c];
    /*
     * End of options.
     */
    if (opt == END) {
      break;
    }
    /*
     * NOP option.
     */
    else if (opt == NOOP) {
      c += 1;
    }
    /*
     * An MSS option with the right option length.
     */
    else if (opt == MSS && options[c + 1] == MSS_LEN) {
      uint16_t omss = ntohs(*(uint16_t*)&options[c + 2]);
      c += MSS_LEN;
      /*
       * An MSS option with the right option length.
       */
      uint16_t nmss = omss > e.m_initialmss ? e.m_initialmss : omss;
      OPT_LOG("initial MSS update: " << e.m_initialmss << " -> " << nmss);
      e.m_initialmss = nmss;
    }
    /*
     * A WSC option with the right option length.
     */
    else if (opt == WSC && options[c + 1] == WSC_LEN) {
      uint8_t wsc = options[c + 2];
      c += WSC_LEN;
      /*
       * RFC1323 limits window scaling to 14. SYN and SYN/ACK do not contain a
       * scaled version of the window size. So we just shift it here.
       */
      e.m_wndscl = wsc > 14 ? 14 : wsc;
      e.m_window >>= e.m_wndscl;
    }
    /*
     * All other options have a length field, so that we easily can
     * skip past them.
     */
    else {
      /*
       * All other options have a length field, so that we easily can skip past
       * them.
       */
      if (options[c + 1] == 0) {
        /*
         * If the length field is zero, the options are malformed and we don't
         * process them further.
         */
        break;
      }
      /*
       * Add the option length and check for overrun
       */
      c += options[c + 1];
      if (c >= 40) {
        /*
         * The option length is invalid, we stop processing the options.
         */
        break;
      }
    }
  }
}

}
