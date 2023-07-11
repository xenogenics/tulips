#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/system/Compiler.h>
#include <iostream>

using namespace std;
using namespace tulips;
using namespace stack;

int
main(int UNUSED argc, UNUSED char** argv)
{
  /*
   * Stack information.
   */
  cout << "ethernet header size is: " << ethernet::HEADER_LEN << "B" << endl;
  cout << "ipv4 header size is: " << ipv4::HEADER_LEN << "B" << endl;
  cout << "tcpv4 header size is: " << tcpv4::HEADER_LEN << "B" << endl;
  cout << "header overhead is: " << tcpv4::HEADER_OVERHEAD << "B" << endl;
  /*
   * MTU references.
   */
  size_t max_1500 = 1500 - ipv4::HEADER_LEN - tcpv4::HEADER_LEN;
  size_t max_9000 = 9000 - ipv4::HEADER_LEN - tcpv4::HEADER_LEN;
  cout << "1500B MTU max payload is: " << max_1500 << "B" << endl;
  cout << "9000B MTU max payload is: " << max_9000 << "B" << endl;
  return 0;
}
