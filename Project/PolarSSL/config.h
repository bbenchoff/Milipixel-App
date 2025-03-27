/*
 * mbedtls_config.h
 * 
 * Minimal configuration for using PolarSSL/Mbed TLS with CodeWarrior Pro 4
 * on Classic Mac OS
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* Include compatibility headers first */
#include "mbedtls_compat.h"

/* System support - disable modern OS features */
#undef MBEDTLS_HAVE_ASM
#undef MBEDTLS_ENTROPY_PLATFORM
#undef MBEDTLS_FS_IO
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_HAVEGE_C

/* use the 'portable c' implemention of multi-precision arithmetic */
#define MBEDTLS_NO_UDBL_DIVISION

/* Disable threading - Classic Mac OS doesn't have POSIX threads */
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_PTHREAD

/* Disable features requiring large buffers or modern CPU */
#undef MBEDTLS_ZLIB_SUPPORT
#undef MBEDTLS_PKCS11_C
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_CMAC_C

/* Disable features we don't need */
#define MBEDTLS_CERTS_C
#define MBEDTLS_DEBUG_C
#define MBEDTLS_ERROR_STRERROR_DUMMY
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C
#undef MBEDTLS_NET_C  /* We'll implement our own using Open Transport */
#undef MBEDTLS_SSL_CACHE_C
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_HAVE_INT64
#undef MBEDTLS_SSL_SESSION_TICKETS
//#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_XTEA_C

/* Reduce memory requirements */
#define MBEDTLS_SSL_MAX_CONTENT_LEN 8192
#define MBEDTLS_MPI_MAX_SIZE 512

/* Core modules we need */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2  /* Use TLS 1.2 as most compatible */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

/* Crypto algorithms - minimal set */
#define MBEDTLS_AES_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ENTROPY_SHA256_ACCUMULATOR
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED


/* RSA is well-supported and widely used */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C

/* Certificate handling */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_DHM_C
#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

/* Random number generation */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT  /* We'll implement our own */

/* Platform customization */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO   mbedtls_free
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO mac_snprintf

/* Use our custom printf */
#define MBEDTLS_PLATFORM_PRINTF_MACRO mac_printf
int mac_printf(const char *format, ...);

/* Error handling */
#define MBEDTLS_ERROR_C

/* Check this configuration */
/* Comment out until ready to test, as it requires many other headers */
#include "check_config.h"

#endif /* MBEDTLS_CONFIG_H */