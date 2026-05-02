/* crypto.cpp -- UPX security enhancement module implementation

   Anti-dump, anti-tamper, encryption, and obfuscation layer.
*/

#include "crypto.h"
#include <cstring>

/*************************************************************************
// Internal: fast non-cryptographic PRNG (xorshift64)
**************************************************************************/

static unsigned xorshift32(unsigned *state) {
    unsigned x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/*************************************************************************
// Internal: rotate key bytes based on position
**************************************************************************/

static byte key_rotate(const upx_crypto_key_t *ck, unsigned pos) {
    unsigned idx = pos % UPX_CRYPTO_KEY_SIZE;
    byte k = ck->key[idx];
    // rotate based on nonce
    byte n = ck->nonce[pos % UPX_CRYPTO_NONCE_SIZE];
    // non-linear mixing
    k = ((k << 3) | (k >> 5)) ^ n;
    k ^= (k >> 4);
    k += (byte)(pos * 0x9D);
    return k;
}

/*************************************************************************
// Key derivation: create a unique key from binary characteristics
**************************************************************************/

void upx_crypto_derive_key(upx_crypto_key_t *ck,
                           const byte *data, unsigned data_len,
                           unsigned seed1, unsigned seed2) {
    if (!ck || !data || data_len == 0)
        return;

    unsigned state = 0xDEADBEEF ^ seed1 ^ seed2;
    unsigned data_mix = 0;

    // Mix data characteristics into key
    for (unsigned i = 0; i < data_len && i < 4096; i++) {
        data_mix = (data_mix << 7) | (data_mix >> 25);
        data_mix ^= data[i] * 0x01000193U;
        data_mix ^= xorshift32(&state);
    }

    // Generate key bytes
    state = data_mix ^ seed1;
    for (int i = 0; i < UPX_CRYPTO_KEY_SIZE; i++) {
        ck->key[i] = (byte)(xorshift32(&state) & 0xFF);
        // Ensure non-zero to avoid weak XOR
        if (ck->key[i] == 0)
            ck->key[i] = (byte)((state >> 16) & 0xFE) + 1;
    }

    // Generate nonce bytes
    state = data_mix ^ seed2;
    for (int i = 0; i < UPX_CRYPTO_NONCE_SIZE; i++) {
        ck->nonce[i] = (byte)(xorshift32(&state) & 0xFF);
        // Ensure non-zero
        if (ck->nonce[i] == 0)
            ck->nonce[i] = (byte)((state >> 8) & 0xFE) + 1;
    }
}

/*************************************************************************
// XOR encryption/decryption with rotating key
// Symmetric: calling again decrypts
**************************************************************************/

void upx_crypto_xor_crypt(byte *data, unsigned len,
                          const upx_crypto_key_t *ck) {
    if (!data || !len || !ck)
        return;

    for (unsigned i = 0; i < len; i++) {
        byte k = key_rotate(ck, i);
        data[i] ^= k;
    }
}

/*************************************************************************
// Generate obfuscated magic bytes (non-printable, random per file)
// Visible printable bytes 0x20-0x7E are avoided
**************************************************************************/

void upx_crypto_obfuscate_magic(upx_obfuscated_magic_t *om,
                                unsigned random_seed) {
    if (!om)
        return;

    unsigned state = random_seed ? random_seed : 0x1337C0DE;

    // Generate random non-printable bytes for magic
    for (int i = 0; i < 4; i++) {
        unsigned r;
        do {
            r = xorshift32(&state) & 0xFF;
        } while ((r >= 0x20 && r <= 0x7E) || r == 0x00 || r == 0xFF);
        om->magic[i] = (byte) r;
    }

    // XOR key for magic verification
    om->xor_key = (byte)(xorshift32(&state) & 0xFF);
    if (om->xor_key >= 0x20 && om->xor_key <= 0x7E)
        om->xor_key ^= 0x80;

    // CRC seed for integrity checks
    om->crc_seed = (byte)(xorshift32(&state) & 0xFF);
    if (om->crc_seed >= 0x20 && om->crc_seed <= 0x7E)
        om->crc_seed ^= 0x80;
}

/*************************************************************************
// Integrity CRC (CRC32-like) for anti-tamper verification
**************************************************************************/

unsigned upx_crypto_integrity_crc(const byte *data, unsigned len,
                                  byte crc_seed) {
    unsigned crc = 0xFFFFFFFF ^ (crc_seed << 24);

    for (unsigned i = 0; i < len; i++) {
        crc ^= data[i] << 24;
        for (int b = 0; b < 8; b++) {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ 0x04C11DB7;
            else
                crc <<= 1;
        }
    }

    return crc ^ 0xFFFFFFFF;
}

/*************************************************************************
// Generate anti-debug shellcode (x86/x64)
// Returns bytes written
**************************************************************************/

unsigned upx_crypto_gen_anti_debug(byte *buf, unsigned buf_size,
                                   unsigned flags, bool is_64bit) {
    if (!buf || buf_size < 64)
        return 0;

    unsigned pos = 0;

    if (flags & UPX_PROTECT_ANTI_DEBUG) {
        if (is_64bit) {
            // x64: Check PEB.BeingDebugged via GS:[0x60]
            // mov rax, gs:[0x60]
            // movzx eax, byte [rax + 2]
            // test eax, eax
            // jz .no_debug
            // int3
            // .no_debug:
            buf[pos++] = 0x65; // GS prefix
            buf[pos++] = 0x48; buf[pos++] = 0x8B; buf[pos++] = 0x04; buf[pos++] = 0x25;
            buf[pos++] = 0x60; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            buf[pos++] = 0x0F; buf[pos++] = 0xB6; buf[pos++] = 0x40; buf[pos++] = 0x02;
            buf[pos++] = 0x48; buf[pos++] = 0x85; buf[pos++] = 0xC0;
            buf[pos++] = 0x74; buf[pos++] = 0x01; // jz +1
            buf[pos++] = 0xCC; // int3 (break if debugger)

            // Check NtGlobalFlag in PEB
            // mov rax, gs:[0x60]
            // test byte [rax + 0xBC], 0x70
            // jz .no_globalflag
            // int3
            // .no_globalflag:
            buf[pos++] = 0x65;
            buf[pos++] = 0x48; buf[pos++] = 0x8B; buf[pos++] = 0x04; buf[pos++] = 0x25;
            buf[pos++] = 0x60; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            buf[pos++] = 0xF6; buf[pos++] = 0x80; buf[pos++] = 0xBC;
            buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x70;
            buf[pos++] = 0x74; buf[pos++] = 0x01;
            buf[pos++] = 0xCC;
        } else {
            // x86: Check PEB.BeingDebugged via FS:[0x30]
            // mov eax, fs:[0x30]
            // movzx eax, byte [eax + 2]
            // test eax, eax
            // jz .no_debug
            // int3
            // .no_debug:
            buf[pos++] = 0x64; buf[pos++] = 0xA1;
            buf[pos++] = 0x30; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            buf[pos++] = 0x0F; buf[pos++] = 0xB6; buf[pos++] = 0x40; buf[pos++] = 0x02;
            buf[pos++] = 0x85; buf[pos++] = 0xC0;
            buf[pos++] = 0x74; buf[pos++] = 0x01;
            buf[pos++] = 0xCC;

            // Check NtGlobalFlag
            // mov eax, fs:[0x30]
            // test byte [eax + 0x68], 0x70
            // jz .no_flag
            // int3
            // .no_flag:
            buf[pos++] = 0x64; buf[pos++] = 0xA1;
            buf[pos++] = 0x30; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            buf[pos++] = 0xF6; buf[pos++] = 0x80;
            buf[pos++] = 0x68; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            buf[pos++] = 0x70;
            buf[pos++] = 0x74; buf[pos++] = 0x01;
            buf[pos++] = 0xCC;
        }
    }

    return pos;
}

/*************************************************************************
// Scramble a name to random non-printable characters (reversible XOR)
**************************************************************************/

void upx_crypto_scramble_name(byte *name, unsigned len, byte key) {
    if (!name || !len || key == 0)
        return;

    for (unsigned i = 0; i < len; i++) {
        if (name[i] == 0)
            break;
        name[i] ^= key;
        // If result is printable ASCII, XOR again with adjacent key
        if (name[i] >= 0x20 && name[i] <= 0x7E) {
            name[i] ^= (byte)(key ^ (i * 0x5D));
        }
        // Ensure non-zero
        if (name[i] == 0)
            name[i] = key ^ (byte)i;
    }
}

/*************************************************************************
// Fill buffer with random non-printable bytes
**************************************************************************/

void upx_crypto_random_nonprintable(byte *buf, unsigned len, unsigned seed) {
    if (!buf || !len)
        return;

    unsigned state = seed ? seed : 0xC0FFEE91;
    for (unsigned i = 0; i < len; i++) {
        unsigned r;
        do {
            r = xorshift32(&state) & 0xFF;
        } while ((r >= 0x20 && r <= 0x7E) || r == 0x00);
        buf[i] = (byte) r;
    }
}
