#pragma once

#include <ostream>
#include <string>

namespace tulips {

enum class Status
{
  Ok,
  InvalidArgument,
  /*
   * Hardware errors
   */
  HardwareError,
  NoMoreResources,
  HardwareLinkLost,
  ResourceBusy,
  /*
   * Data errors
   */
  NoDataAvailable,
  CorruptedData,
  IncompleteData,
  UnsupportedData,
  /*
   * Protocol errors
   */
  ProtocolError,
  SslError,
  UnsupportedProtocol,
  /*
   * Connection errors
   */
  HardwareTranslationMissing,
  InvalidConnection,
  NotConnected,
  /*
   * Operation errors
   */
  OperationInProgress,
  OperationCompleted,
  UnsupportedOperation
};

inline std::string
toString(const Status s)
{
  switch (s) {
    case Status::Ok:
      return "Ok";
    case Status::InvalidArgument:
      return "InvalidArgument";
    case Status::HardwareError:
      return "HardwareError";
    case Status::NoMoreResources:
      return "NoMoreResources";
    case Status::HardwareLinkLost:
      return "HardwareLinkLost";
    case Status::ResourceBusy:
      return "ResourceBusy";
    case Status::NoDataAvailable:
      return "NoDataAvailable";
    case Status::CorruptedData:
      return "CorruptedData";
    case Status::IncompleteData:
      return "IncompleteData";
    case Status::UnsupportedData:
      return "UnsupportedData";
    case Status::ProtocolError:
      return "ProtocolError";
    case Status::SslError:
      return "SslError";
    case Status::UnsupportedProtocol:
      return "UnsupportedProtocol";
    case Status::HardwareTranslationMissing:
      return "HardwareTranslationMissing";
    case Status::InvalidConnection:
      return "InvalidConnection";
    case Status::NotConnected:
      return "NotConnected";
    case Status::OperationInProgress:
      return "OperationInProgress";
    case Status::OperationCompleted:
      return "OperationCompleted";
    case Status::UnsupportedOperation:
      return "UnsupportedOperation";
  }
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
  return "";
#endif
}

inline std::ostream&
operator<<(std::ostream& os, const Status& status)
{
  os << toString(status);
  return os;
}

}
