#pragma once

#include <tulips/apps/Options.h>
#include <tulips/transport/Device.h>
#include <string>
#include <vector>

namespace tulips::apps::tcplatency {

namespace Client {

int run(Options const& options, transport::Device::Ref dev);

}

namespace Server {

int run(Options const& options, transport::Device::Ref dev);

}

}
