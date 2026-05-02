/* crypto.h -- UPX security enhancement module

   Anti-dump, anti-tamper, encryption, and obfuscation layer.
*/

#pragma once

#include "conf.h"

/*************************************************************************
// Encryption key (per-file unique, derived from binary characteristics)
**************************************************************************/

#define UPX_CRYPTO_KEY_SIZE   32
#define UPX_CRYPTO_NONCE_SIZE 16
#define UPX_CRYPTO_MAGIC_SIZE 8

struct upx_crypto_key_t {
    byte key[UPX_CRYPTO_KEY_SIZE];
    byte nonce[UPX_CRYPTO_NONCE_SIZE];
};

/*************************************************************************
// Obfuscated pack header magic - replaces "UPX!"
// Generated randomly per pack operation
**************************************************************************/

struct upx_obfuscated_magic_t {
    byte magic[4];    // obfuscated magic (random non-printable bytes)
    byte xor_key;     // XOR key used to obfuscate the magic
    byte crc_seed;    // seed for integrity check
};

/*************************************************************************
// Anti-debug / anti-dump flags
**************************************************************************/

enum {
    UPX_PROTECT_ANTI_DEBUG    = 1 << 0,  // PEB.BeingDebugged check
    UPX_PROTECT_ANTI_DUMP     = 1 << 1,  // erase PE header after load
    UPX_PROTECT_CHECK_INTEGRITY = 1 << 2, // CRC integrity verification
    UPX_PROTECT_OBFUSCATE_IMPORTS = 1 << 3, // scramble import names
    UPX_PROTECT_ENCRYPT_DATA  = 1 << 4,  // XOR-encrypt compressed data
    UPX_PROTECT_ALL           = 0xFF
};

/*************************************************************************
// Crypto API
**************************************************************************/

// Derive a unique encryption key from binary data
void upx_crypto_derive_key(upx_crypto_key_t *ck,
                           const byte *data, unsigned data_len,
                           unsigned seed1, unsigned seed2);

// XOR-encrypt/decrypt data in-place with rotating key
void upx_crypto_xor_crypt(byte *data, unsigned len,
                          const upx_crypto_key_t *ck);

// Generate obfuscated magic bytes (non-printable) for pack header
void upx_crypto_obfuscate_magic(upx_obfuscated_magic_t *om,
                                unsigned random_seed);

// Compute integrity CRC of data
unsigned upx_crypto_integrity_crc(const byte *data, unsigned len,
                                  byte crc_seed);

// Generate anti-debug shellcode snippet (x86/x64)
// Returns size of generated code
unsigned upx_crypto_gen_anti_debug(byte *buf, unsigned buf_size,
                                   unsigned flags, bool is_64bit);

// Scramble a name string to random non-printable chars (reversible)
void upx_crypto_scramble_name(byte *name, unsigned len, byte key);

// Generate random non-printable bytes
void upx_crypto_random_nonprintable(byte *buf, unsigned len, unsigned seed);
