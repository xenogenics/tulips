#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <iostream>
#include <sstream>
#include <linenoise/linenoise.h>
#include <uspace/ofed/Connection.h>
#include <uspace/ofed/State.h>

namespace tulips::tools::uspace::ofed::connection {

/*
 * Close.
 */

class Close : public utils::Command
{
public:
  Close() : Command("close a connection"), m_hint(" <id>") {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: close ID" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 2) {
      help(args);
      return;
    }
    /*
     * Parse the port socket.
     */
    api::Client::ID c;
    std::istringstream(args[1]) >> c;
    /*
     * Check if the connection exists.
     */
    if (s.ids.count(c) == 0) {
      std::cout << "No such connection." << std::endl;
      return;
    }
    /*
     * Grab and close the connection.
     */
    switch (s.poller.close(c)) {
      case Status::Ok: {
        std::cout << "Connection closed." << std::endl;
        s.ids.erase(c);
        break;
      }
      case Status::NotConnected: {
        std::cout << "No such connection." << std::endl;
        break;
      }
      default: {
        std::cout << "Error." << std::endl;
        break;
      }
    }
  }

  char* hint(UNUSED utils::State& s, int* color, UNUSED int* bold) override
  {
    *color = LN_GREEN;
    return (char*)m_hint.c_str();
  }

private:
  std::string m_hint;
};

/*
 * Connect.
 */

class Connect : public utils::Command
{
public:
  Connect() : Command("connect to a remote TCP server"), m_hint(" <ip> <port>")
  {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: connect IP PORT" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  try {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 3) {
      help(args);
      return;
    }
    /*
     * Parse the IP address.
     */
    stack::ipv4::Address ip(args[1]);
    /*
     * Parse the port number.
     */
    uint16_t port;
    std::istringstream(args[2]) >> port;
    /*
     * Create a connection.
     */
    api::Client::ID id;
    switch (s.poller.connect(ip, port, id)) {
      case Status::Ok: {
        std::cout << "OK - " << id << std::endl;
        s.ids.insert(id);
        break;
      }
      default: {
        std::cout << "Error." << std::endl;
        break;
      }
    }
  } catch (...) {
    help(args);
  }

  char* hint(UNUSED utils::State& s, int* color, UNUSED int* bold) override
  {
    *color = LN_GREEN;
    return (char*)m_hint.c_str();
  }

private:
  std::string m_hint;
};

/*
 * List.
 */

class List : public utils::Command
{
public:
  List() : Command("list active connections") {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "List active connections." << std::endl;
  }

  void execute(utils::State& us, UNUSED utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check connections.
     */
    if (s.ids.empty()) {
      std::cout << "No active connections." << std::endl;
    } else {
      /*
       * Print the header.
       */
      std::cout << std::setw(7) << std::left << "ID " << std::setw(16)
                << std::left << "IP " << std::setw(12) << std::left
                << "Local port" << std::setw(11) << std::left << "Remote port"
                << std::right << std::endl;
      /*
       * Print the connections.
       */
      IDs::iterator it;
      stack::ipv4::Address ip;
      stack::tcpv4::Port lport, rport;
      for (it = s.ids.begin(); it != s.ids.end(); it++) {
        s.poller.get(*it, ip, lport, rport);
        std::cout << std::setw(7) << std::left << *it << std::setw(16)
                  << std::left << ip.toString() << std::setw(12) << std::left
                  << lport << std::setw(11) << std::left << rport << std::right
                  << std::endl;
      }
    }
  }
};

class Write : public utils::Command
{
public:
  Write()
    : Command("write data to an active connection"), m_hint(" <id> <data> ...")
  {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: write ID DATA [DATA ...]" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() < 3) {
      help(args);
      return;
    }
    /*
     * Parse the port socket.
     */
    api::Client::ID id;
    std::istringstream(args[1]) >> id;
    /*
     * Check if the connection exists.
     */
    if (s.ids.count(id) == 0) {
      std::cout << "No such connection." << std::endl;
      return;
    }
    /*
     * Write data.
     */
    std::string data;
    std::vector<std::string> rest(args.begin() + 2, args.end());
    system::utils::join(rest, ' ', data);
    switch (s.poller.write(id, data)) {
      case Status::Ok: {
        std::cout << "OK - " << data.length() << "." << std::endl;
        break;
      }
      default: {
        std::cout << "Error." << std::endl;
      }
    }
  }

  char* hint(UNUSED utils::State& s, int* color, UNUSED int* bold) override
  {
    *color = LN_GREEN;
    return (char*)m_hint.c_str();
  }

private:
  std::string m_hint;
};

/*
 * Helpers.
 */

void
populate(utils::Commands& cmds)
{
  cmds["close"] = new Close;
  cmds["connect"] = new Connect;
  cmds["list"] = new List;
  cmds["write"] = new Write;
}

}
