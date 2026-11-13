// PhantomAuth.hpp — header-only license client for the PhantomX loader.
//
// Uses only built-in Windows APIs (WinHTTP + BCrypt + Crypt32): no extra libs.
// Works for x86 and x64, MSVC (C++17).
//
// Flow:
//   1. Loader sends { key, hwid, nonce, version } to POST /api/v1/auth
//   2. Server answers { payload, sig } — payload is JSON signed with ECDSA P-256
//   3. Loader verifies the signature with the embedded public key and checks
//      that nonce / key / hwid match what it sent (blocks replay + fake servers)
//
// Usage:
//   phx::Config cfg;
//   cfg.host = L"auth.example.com"; cfg.port = 443; cfg.https = true;
//   cfg.publicKey = kServerPublicKey; cfg.loaderVersion = 1;
//   phx::Result r = phx::Authenticate(cfg, userKey);
//   if (!r.ok) { MessageBoxA(nullptr, r.message.c_str(), "Auth", MB_ICONERROR); return; }

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>

#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#endif // MinGW: link with -lwinhttp -lbcrypt -lcrypt32 -ladvapi32

namespace phx {

struct Config {
    const wchar_t*       host          = L"127.0.0.1";
    INTERNET_PORT        port          = 8080;
    bool                 https         = false;   // ALWAYS true in production
    const wchar_t*       path          = L"/api/v1/auth";
    const unsigned char* publicKey     = nullptr; // 64 bytes: X||Y (from `npm run admin -- pubkey`)
    int                  loaderVersion = 1;
    DWORD                timeoutMs     = 10000;
};

struct Result {
    bool        ok         = false;
    std::string status;            // ok | invalid_key | banned | expired | hwid_mismatch | outdated | network_error | bad_signature | ...
    std::string message;
    long long   expiresAt  = 0;    // unix seconds, 0 = lifetime
    long long   serverTime = 0;
};

namespace detail {

inline bool Sha256(const void* data, size_t len, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h  = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
            ok = BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0) == 0 &&
                 BCryptFinishHash(h, out, 32, 0) == 0;
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

inline std::string Hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

inline std::string RandomHex(size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    if (BCryptGenRandom(nullptr, buf.data(), (ULONG)bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
    return Hex(buf.data(), bytes);
}

// HWID = SHA-256( MachineGuid | C: volume serial ). Stable across reboots,
// changes on Windows reinstall (admin can reset the lock).
inline std::string ComputeHwid() {
    std::string material;

    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS) {
        char guid[128] = {};
        DWORD size = sizeof(guid) - 1, type = 0;
        if (RegQueryValueExA(key, "MachineGuid", nullptr, &type, (LPBYTE)guid, &size) == ERROR_SUCCESS && type == REG_SZ)
            material += guid;
        RegCloseKey(key);
    }

    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%08lX", (unsigned long)serial);
        material += "|";
        material += buf;
    }

    unsigned char digest[32];
    if (material.empty() || !Sha256(material.data(), material.size(), digest)) return {};
    return Hex(digest, 32);
}

inline bool Base64Decode(const std::string& in, std::vector<unsigned char>& out) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr))
        return false;
    out.resize(len);
    if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr))
        return false;
    out.resize(len);
    return true;
}

inline std::string JsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
                else o += c;
        }
    }
    return o;
}

// Minimal extractor for the flat JSON objects this server returns.
inline size_t JsonFindValue(const std::string& j, const char* name) {
    std::string needle = std::string("\"") + name + "\":";
    size_t p = j.find(needle);
    return p == std::string::npos ? p : p + needle.size();
}

inline bool JsonGetString(const std::string& j, const char* name, std::string& out) {
    size_t p = JsonFindValue(j, name);
    if (p == std::string::npos || p >= j.size() || j[p] != '"') return false;
    out.clear();
    for (size_t i = p + 1; i < j.size(); ++i) {
        char c = j[i];
        if (c == '"') return true;
        if (c == '\\' && i + 1 < j.size()) {
            char e = j[++i];
            switch (e) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case 'u': i += 4; out += '?'; break; // not used by this server
                default:  out += e;
            }
        } else {
            out += c;
        }
    }
    return false;
}

inline bool JsonGetInt(const std::string& j, const char* name, long long& out) {
    size_t p = JsonFindValue(j, name);
    if (p == std::string::npos) return false;
    char* end = nullptr;
    out = _strtoi64(j.c_str() + p, &end, 10);
    return end != j.c_str() + p;
}

inline bool JsonGetBool(const std::string& j, const char* name, bool& out) {
    size_t p = JsonFindValue(j, name);
    if (p == std::string::npos) return false;
    if (j.compare(p, 4, "true") == 0)  { out = true;  return true; }
    if (j.compare(p, 5, "false") == 0) { out = false; return true; }
    return false;
}

inline bool VerifySignature(const unsigned char pub[64],
                            const std::vector<unsigned char>& data,
                            const std::vector<unsigned char>& sig) {
    if (!pub || sig.size() != 64) return false;

    unsigned char hash[32];
    if (!Sha256(data.data(), data.size(), hash)) return false;

    unsigned char blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob);
    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey   = 32;
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), pub, 64);

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, blob, sizeof(blob), 0) == 0) {
            ok = BCryptVerifySignature(key, nullptr, hash, 32, (PUCHAR)sig.data(), 64, 0) == 0;
            BCryptDestroyKey(key);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

inline bool HttpPost(const Config& cfg, const std::string& body, std::string& response, DWORD& statusCode) {
    bool ok = false;
    HINTERNET s = WinHttpOpen(L"PhantomX-Loader/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) // WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY needs Win 8.1+
        s = WinHttpOpen(L"PhantomX-Loader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return false;
    WinHttpSetTimeouts(s, cfg.timeoutMs, cfg.timeoutMs, cfg.timeoutMs, cfg.timeoutMs);

    HINTERNET c = WinHttpConnect(s, cfg.host, cfg.port, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, L"POST", cfg.path, nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, cfg.https ? WINHTTP_FLAG_SECURE : 0)
                    : nullptr;
    if (r) {
        const wchar_t* headers = L"Content-Type: application/json\r\n";
        if (WinHttpSendRequest(r, headers, (DWORD)-1L, (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0) &&
            WinHttpReceiveResponse(r, nullptr)) {
            DWORD size = sizeof(statusCode);
            WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
            response.clear();
            DWORD avail = 0;
            ok = true;
            while (WinHttpQueryDataAvailable(r, &avail) && avail > 0) {
                if (response.size() + avail > 64 * 1024) { ok = false; break; }
                std::string chunk(avail, '\0');
                DWORD read = 0;
                if (!WinHttpReadData(r, &chunk[0], avail, &read)) { ok = false; break; }
                response.append(chunk.data(), read);
            }
        }
        WinHttpCloseHandle(r);
    }
    if (c) WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
    return ok;
}

inline Result Fail(const char* status, const char* message) {
    Result r;
    r.status  = status;
    r.message = message;
    return r;
}

} // namespace detail

inline std::string GetHwid() { return detail::ComputeHwid(); }

inline Result Authenticate(const Config& cfg, std::string key) {
    using namespace detail;

    // trim + uppercase, same as the server
    while (!key.empty() && isspace((unsigned char)key.back())) key.pop_back();
    while (!key.empty() && isspace((unsigned char)key.front())) key.erase(key.begin());
    for (char& ch : key) ch = (char)toupper((unsigned char)ch);
    if (key.empty()) return Fail("bad_request", "Please enter a license key.");
    if (!cfg.publicKey) return Fail("config_error", "Public key not configured.");

    const std::string hwid  = ComputeHwid();
    const std::string nonce = RandomHex(16);
    if (hwid.empty() || nonce.empty()) return Fail("hwid_error", "Could not read hardware ID.");

    std::string body = "{\"key\":\"" + JsonEscape(key) + "\",\"hwid\":\"" + hwid +
                       "\",\"nonce\":\"" + nonce + "\",\"version\":" + std::to_string(cfg.loaderVersion) + "}";

    std::string resp;
    DWORD code = 0;
    if (!HttpPost(cfg, body, resp, code)) return Fail("network_error", "Cannot reach the auth server.");
    if (code == 429) return Fail("rate_limited", "Too many attempts. Please wait a minute.");
    if (code != 200) return Fail("server_error", "Auth server returned an error.");

    std::string payloadB64, sigB64;
    if (!JsonGetString(resp, "payload", payloadB64) || !JsonGetString(resp, "sig", sigB64))
        return Fail("bad_response", "Invalid response from server.");

    std::vector<unsigned char> payloadBytes, sig;
    if (!Base64Decode(payloadB64, payloadBytes) || !Base64Decode(sigB64, sig))
        return Fail("bad_response", "Invalid response from server.");

    if (!VerifySignature(cfg.publicKey, payloadBytes, sig))
        return Fail("bad_signature", "Server signature check failed.");

    const std::string p(payloadBytes.begin(), payloadBytes.end());
    std::string rNonce, rKey, rHwid;
    if (!JsonGetString(p, "nonce", rNonce) || rNonce != nonce ||
        !JsonGetString(p, "key", rKey)     || rKey   != key   ||
        !JsonGetString(p, "hwid", rHwid)   || rHwid  != hwid)
        return Fail("bad_signature", "Server response mismatch.");

    Result r;
    bool okFlag = false;
    JsonGetBool(p, "ok", okFlag);
    JsonGetString(p, "status", r.status);
    JsonGetString(p, "message", r.message);
    JsonGetInt(p, "expires_at", r.expiresAt);
    JsonGetInt(p, "server_time", r.serverTime);
    r.ok = okFlag && r.status == "ok";
    return r;
}

} // namespace phx
