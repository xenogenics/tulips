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

std::string toString(const Status s);
std::ostream& operator<<(std::ostream& os, const Status& status);

}
