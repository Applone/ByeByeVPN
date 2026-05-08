#ifndef NETWORK_TCP_ASYNC_SCAN_H
#define NETWORK_TCP_ASYNC_SCAN_H

#include <string>
#include <vector>

#include "port_scan.h"

std::vector<TcpOpen> scan_tcp_async(const std::string& host,
                                    const std::vector<int>& ports,
                                    int threads,
                                    int to_ms,
                                    ScanStats* stats);

#endif // NETWORK_TCP_ASYNC_SCAN_H
