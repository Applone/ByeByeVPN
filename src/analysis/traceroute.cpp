#include "traceroute.h"
#include "../network/socket_sys.h"
#include <chrono>
#include <cstring>
#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef _WIN32
#include <iphlpapi.h>
#include <icmpapi.h>
#endif


