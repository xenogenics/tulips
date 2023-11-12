#include <tulips/api/Defaults.h>
#include <tulips/system/Compiler.h>

namespace tulips::api::defaults {

void*
ClientDelegate::onConnected(UNUSED Client::ID const& id,
                            UNUSED void* const cookie,
                            UNUSED const Timestamp ts)
{
  return nullptr;
}

Action
ClientDelegate::onAcked(UNUSED Client::ID const& id, UNUSED void* const cookie,
                        UNUSED const Timestamp ts, UNUSED const uint32_t savl,
                        UNUSED uint8_t* const sdat, UNUSED uint32_t& slen)
{
  return Action::Continue;
}

Action
ClientDelegate::onNewData(UNUSED Client::ID const& id,
                          UNUSED void* const cookie,
                          UNUSED const uint8_t* const rdat,
                          UNUSED const uint32_t rlen, UNUSED const Timestamp ts,
                          UNUSED const uint32_t savl,
                          UNUSED uint8_t* const sdat, UNUSED uint32_t& slen)
{
  return Action::Continue;
}

void
ClientDelegate::onClosed(UNUSED Client::ID const& id, UNUSED void* const cookie,
                         UNUSED const Timestamp ts)
{}

void*
ServerDelegate::onConnected(UNUSED Server::ID const& id,
                            UNUSED void* const cookie,
                            UNUSED const Timestamp ts)
{
  return nullptr;
}

Action
ServerDelegate::onAcked(UNUSED Client::ID const& id, UNUSED void* const cookie,
                        UNUSED const Timestamp ts, UNUSED const uint32_t savl,
                        UNUSED uint8_t* const sdat, UNUSED uint32_t& slen)
{
  return Action::Continue;
}

Action
ServerDelegate::onNewData(UNUSED Server::ID const& id,
                          UNUSED void* const cookie,
                          UNUSED const uint8_t* const rdat,
                          UNUSED const uint32_t rlen, UNUSED const Timestamp ts,
                          UNUSED const uint32_t savl,
                          UNUSED uint8_t* const sdat, UNUSED uint32_t& slen)
{
  return Action::Continue;
}

void
ServerDelegate::onClosed(UNUSED Server::ID const& id, UNUSED void* const cookie,
                         UNUSED const Timestamp ts)
{}

}
