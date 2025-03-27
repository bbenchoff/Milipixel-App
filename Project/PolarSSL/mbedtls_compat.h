/*
 * mbedtls_compat.h
 * 
 * Compatibility header for using PolarSSL/Mbed TLS with CodeWarrior Pro 4
 * on Classic Mac OS
 */

#ifndef MBEDTLS_COMPAT_H
#define MBEDTLS_COMPAT_H

/* Include our stdint replacements */
#include "mac_stdint.h"

/* Include Mac OS headers we'll need */
#include <Types.h>
#include <Memory.h>
#include <OSUtils.h>

/* Define size_t if not already defined */
#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned long size_t;
#endif

/* Define va_list if not already defined */
#ifndef _VA_LIST
#define _VA_LIST
typedef char* va_list;
#endif

/* 
 * Handle type conflicts with Mac OS types 
 * Temporarily redefine Mac OS types before including mbedtls headers
 */
#define Byte        Mac_Byte
#define Word        Mac_Word
#define Boolean     Mac_Boolean
#define Size        Mac_Size

/* Define C99 types and functions needed by mbedtls */
#ifndef bool
typedef int                 bool;
#define true                1
#define false               0
#endif

/* Define inline support */
#ifndef inline
#define inline              
#endif

/* 
 * Define platform endianness
 * Classic Mac on 68K is big-endian
 */
#define MBEDTLS_BYTE_ORDER MBEDTLS_BIG_ENDIAN

/* 
 * Time functions - Classic Mac OS uses unsigned long for time
 * and doesn't have time_t/struct tm as in modern C
 */
#ifndef time_t
typedef unsigned long       time_t;
#endif

/* 
 * Define snprintf replacement 
 * Classic Mac OS doesn't have standard snprintf
 */
int mac_snprintf(char* str, size_t size, const char* format, ...);
#define snprintf mac_snprintf

/* 
 * Memory allocation functions
 * Map to Mac OS Memory Manager
 */
void* mbedtls_calloc(size_t count, size_t size);
void mbedtls_free(void* ptr);

/* Simple implementations of these functions */
/* Define this to avoid compiler errors, but it will be implemented in C file */
int mac_printf(const char *format, ...);

/* Add stubs for various C library functions that mbedTLS might use */
#define vsnprintf mac_vsnprintf
int mac_vsnprintf(char* str, size_t size, const char* format, va_list ap);

/* Add other compatibility functions as needed */

/* Include this before any mbedtls headers */

#endif /* MBEDTLS_COMPAT_H */