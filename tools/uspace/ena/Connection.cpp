#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <iostream>
#include <sstream>
#include <linenoise/linenoise.h>
#include <uspace/ena/Connection.h>
#include <uspace/ena/State.h>

namespace tulips::tools::uspace::ena::connection {

/*
 * Connect.
 */

class Connect : public utils::Command
{
public:
  Connect()
    : Command("connect to a remote TCP server"), m_hint(" <poller> <ip> <port>")
  {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: connect POLLER IP PORT" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  try {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 4) {
      help(args);
      return;
    }
    /*
     * Parse the poller ID.
     */
    size_t poller;
    std::istringstream(args[1]) >> poller;
    /*
     * Check that the poller index is valid.
     */
    if (poller >= s.pollers.size()) {
      std::cout << "Invalid poller ID: " << poller << "." << std::endl;
      return;
    }
    /*
     * Parse the IP address.
     */
    stack::ipv4::Address ip(args[2]);
    /*
     * Parse the port number.
     */
    uint16_t port;
    std::istringstream(args[3]) >> port;
    /*
     * Create a connection.
     */
    api::Client::ID id;
    switch (s.pollers[poller]->connect(ip, port, id)) {
      case Status::Ok: {
        std::cout << "OK - " << id << std::endl;
        s.ids[poller].insert(id);
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
 * Disconnect.
 */

class Disconnect : public utils::Command
{
public:
  Disconnect()
    : Command("disconnect from a remote server"), m_hint(" <poller> <id>")
  {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: disconnect POLLER ID" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 3) {
      help(args);
      return;
    }
    /*
     * Parse the poller ID.
     */
    size_t poller;
    std::istringstream(args[1]) >> poller;
    /*
     * Parse the port socket.
     */
    api::Client::ID c;
    std::istringstream(args[2]) >> c;
    /*
     * Make sure the poller is part of the index.
     */
    if (s.ids.count(poller) == 0) {
      std::cout << "No connection for poller " << poller << std::endl;
      return;
    }
    /*
     * Make sure the connection is open.
     */
    if (s.ids[poller].count(c) == 0) {
      std::cout << "Connection " << c << " for poller " << poller
                << " is not open" << std::endl;
      return;
    }
    /*
     * Grab and close the connection.
     */
    auto ret = s.pollers[poller]->close(c);
    switch (ret) {
      case Status::Ok: {
        std::cout << "Connection closed." << std::endl;
        s.ids[poller].erase(c);
        break;
      }
      case Status::NotConnected: {
        std::cout << "Not connected." << std::endl;
        break;
      }
      default: {
        std::cout << "Error: " << toString(ret) << std::endl;
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
      stack::ipv4::Address ip;
      stack::tcpv4::Port lport, rport;
      /*
       * Print the header.
       */
      std::cout << std::setw(7) << std::left << "Poller" << std::setw(7)
                << std::left << "ID " << std::setw(16) << std::left << "IP "
                << std::setw(12) << std::left << "Local port" << std::setw(11)
                << std::left << "Remote port" << std::right << std::endl;
      /*
       * Print the connections.
       */
      for (auto& [poller, ids] : s.ids) {
        for (auto& id : ids) {
          s.pollers[poller]->get(id, ip, lport, rport);
          std::cout << std::setw(7) << std::left << poller << std::setw(7)
                    << std::left << id << std::setw(16) << std::left
                    << ip.toString() << std::setw(12) << std::left << lport
                    << std::setw(11) << std::left << rport << std::right
                    << std::endl;
        }
      }
    }
  }
};

class Write : public utils::Command
{
public:
  Write()
    : Command("write data to an active connection")
    , m_hint(" <poller> <id> <data> ...")
  {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: write POLLER ID DATA [DATA ...]" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() < 4) {
      help(args);
      return;
    }
    /*
     * Parse the poller ID.
     */
    size_t poller;
    std::istringstream(args[1]) >> poller;
    /*
     * Parse the port socket.
     */
    api::Client::ID c;
    std::istringstream(args[2]) >> c;
    /*
     * Make sure the poller is part of the index.
     */
    if (s.ids.count(poller) == 0) {
      std::cout << "No connection for poller " << poller << std::endl;
      return;
    }
    /*
     * Make sure the connection is open.
     */
    if (s.ids[poller].count(c) == 0) {
      std::cout << "Connection " << c << " for poller " << poller
                << " is not open" << std::endl;
      return;
    }
    /*
     * Write data.
     */
    std::string data;
    std::vector<std::string> rest(args.begin() + 2, args.end());
    system::utils::join(rest, ' ', data);
    switch (s.pollers[poller]->write(c, data)) {
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
populate(UNUSED utils::Commands& cmds)
{
  cmds["connect"] = new Connect;
  cmds["disconnect"] = new Disconnect;
  cmds["list-connections"] = new List;
  cmds["write"] = new Write;
}

}
