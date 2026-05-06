#include "verdict.h"
#include <openssl/opensslv.h>

static bool hardcoded_ja3_supported() {
#if defined(OPENSSL_VERSION_MAJOR) && defined(OPENSSL_VERSION_MINOR)
    return OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0;
#else
    return false;
#endif
}

// Returns the JA3 signature of our own OpenSSL stack.
// Hard-coded only for OpenSSL 3.0.x; newer library defaults may differ.
Ja3Info our_openssl_ja3_signature() {
    Ja3Info j;
    if (!hardcoded_ja3_supported()) return j;
    j.version    = "771";
    j.ciphers    = "4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53";
    j.extensions = "0,11,10,35,22,23,13,43,45,51";
    j.groups     = "29,23,30,25,24";
    j.ec_formats = "0";
    j.ja3_hash   = "0cce74b0d9b7f8528fb2181588d23793";
    return j;
}
