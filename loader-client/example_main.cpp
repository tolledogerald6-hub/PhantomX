// Example: console loader that asks for a key and authenticates.
// Build (Developer Command Prompt):  cl /std:c++17 /EHsc /O2 example_main.cpp
#include "PhantomAuth.hpp"
#include <iostream>
#include <ctime>

// Replace with the output of:  npm run admin -- pubkey   (in auth-server/)
static const unsigned char kServerPublicKey[64] = { 0 };

int main() {
    phx::Config cfg;
    cfg.host          = L"127.0.0.1";   // e.g. L"auth.yourdomain.com"
    cfg.port          = 8080;           // 443 in production
    cfg.https         = false;          // true in production
    cfg.publicKey     = kServerPublicKey;
    cfg.loaderVersion = 1;

    std::string key;
    std::cout << "Enter license key: ";
    std::getline(std::cin, key);

    phx::Result r = phx::Authenticate(cfg, key);
    if (!r.ok) {
        std::cout << "[x] " << r.message << " (" << r.status << ")\n";
        return 1;
    }

    std::cout << "[+] " << r.message << "\n";
    if (r.expiresAt == 0) {
        std::cout << "    License: LIFETIME\n";
    } else {
        long long left = r.expiresAt - r.serverTime;
        std::cout << "    Days left: " << left / 86400 << "d " << (left % 86400) / 3600 << "h\n";
    }
    // ... continue loading here ...
    return 0;
}
