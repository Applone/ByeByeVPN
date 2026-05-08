#ifndef NETWORK_OPENSSL_RUNTIME_H
#define NETWORK_OPENSSL_RUNTIME_H

#include "socket_sys.h"

#include <string>

struct ssl_st;
using SSL = ssl_st;

bool openssl_runtime_init(std::string* err = nullptr);
void openssl_runtime_cleanup();

bool ssl_attach_socket(SSL* ssl, SOCKET s, std::string* err = nullptr);

#endif // NETWORK_OPENSSL_RUNTIME_H
