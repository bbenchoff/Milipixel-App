/*
 * mac_stdint.h
 * 
 * Compatibility header providing C99 fixed-width integer types
 * for CodeWarrior Pro 4 on Classic Mac OS
 */

#ifndef MAC_STDINT_H
#define MAC_STDINT_H

/* Include Mac OS types */
#include <Types.h>

/* 
 * Define fixed width integer types based on Mac OS types
 * Classic Mac OS on 68K processors is big-endian
 */

/* Exact-width signed integer types */
typedef signed char        int8_t;
typedef short              int16_t;
typedef long               int32_t;

/* Exact-width unsigned integer types */
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned long      uint32_t;

/* Minimum-width signed integer types */
typedef signed char        int_least8_t;
typedef short              int_least16_t;
typedef long               int_least32_t;

/* Minimum-width unsigned integer types */
typedef unsigned char      uint_least8_t;
typedef unsigned short     uint_least16_t;
typedef unsigned long      uint_least32_t;

/* Fast minimum-width signed integer types */
typedef signed char        int_fast8_t;
typedef short              int_fast16_t;
typedef long               int_fast32_t;

/* Fast minimum-width unsigned integer types */
typedef unsigned char      uint_fast8_t;
typedef unsigned short     uint_fast16_t;
typedef unsigned long      uint_fast32_t;

/* Greatest-width integer types */
typedef long               intmax_t;
typedef unsigned long      uintmax_t;

/* Integer type capable of holding a pointer */
typedef long               intptr_t;
typedef unsigned long      uintptr_t;

/* Limits of exact-width integer types */
#define INT8_MIN           (-128)
#define INT16_MIN          (-32767-1)
#define INT32_MIN          (-2147483647L-1)

#define INT8_MAX           127
#define INT16_MAX          32767
#define INT32_MAX          2147483647L

#define UINT8_MAX          255U
#define UINT16_MAX         65535U
#define UINT32_MAX         4294967295UL

/* Limits of minimum-width integer types */
#define INT_LEAST8_MIN     INT8_MIN
#define INT_LEAST16_MIN    INT16_MIN
#define INT_LEAST32_MIN    INT32_MIN

#define INT_LEAST8_MAX     INT8_MAX
#define INT_LEAST16_MAX    INT16_MAX
#define INT_LEAST32_MAX    INT32_MAX

#define UINT_LEAST8_MAX    UINT8_MAX
#define UINT_LEAST16_MAX   UINT16_MAX
#define UINT_LEAST32_MAX   UINT32_MAX

/* Limits of fastest minimum-width integer types */
#define INT_FAST8_MIN      INT8_MIN
#define INT_FAST16_MIN     INT16_MIN
#define INT_FAST32_MIN     INT32_MIN

#define INT_FAST8_MAX      INT8_MAX
#define INT_FAST16_MAX     INT16_MAX
#define INT_FAST32_MAX     INT32_MAX

#define UINT_FAST8_MAX     UINT8_MAX
#define UINT_FAST16_MAX    UINT16_MAX
#define UINT_FAST32_MAX    UINT32_MAX

/* Limits of integer types capable of holding object pointers */
#define INTPTR_MIN         INT32_MIN
#define INTPTR_MAX         INT32_MAX
#define UINTPTR_MAX        UINT32_MAX

/* Limits of greatest-width integer types */
#define INTMAX_MIN         INT32_MIN
#define INTMAX_MAX         INT32_MAX
#define UINTMAX_MAX        UINT32_MAX

#define SIZE_MAX			UINT32_MAX

/* 
 * 64-bit types are not natively supported in Classic Mac OS on 68K
 * So here they are
 */
 
typedef struct {
	uint32_t high;
	uint32_t low;
} uint64_t;

typedef struct {
	int32_t high;
	int32_t low;
} int64_t;

#define UINT64_C(h, l) ((uint64_t){(h), (l)})
#define INT64_C(h, l) ((int64_t){(h), (l)})

#define UINT64_LOW(x) ((x).low)
#define UINT64_HIGH(x) ((x).high)

#endif /* MAC_STDINT_H */