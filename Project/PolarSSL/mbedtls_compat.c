/*
 * mbedtls_compat.c
 * 
 * Implementation of compatibility functions for PolarSSL/Mbed TLS
 * with CodeWarrior Pro 4 on Classic Mac OS
 */

#include "mbedtls_compat.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <Memory.h>

/*
 * A simplified implementation of snprintf for Classic Mac OS
 */
int mac_snprintf(char* str, size_t size, const char* format, ...) {
    int result;
    va_list args;
    char temp_buffer[4096]; /* Adjust size as needed */
    
    /* If buffer size is 0 or negative, do nothing */
    if (size <= 0) return -1;
    
    /* Format the string using vsprintf */
    va_start(args, format);
    
    /* Use a temporary buffer to avoid overflow */
    result = vsprintf(temp_buffer, format, args);
    
    va_end(args);
    
    /* Copy result to output buffer with size limit */
    if (result >= 0) {
        size_t copy_size = (result < size - 1) ? result : size - 1;
        memcpy(str, temp_buffer, copy_size);
        str[copy_size] = '\0'; /* Ensure null termination */
    } else {
        if (size > 0) str[0] = '\0';
    }
    
    return result;
}

/*
 * A simplified implementation of vsnprintf for Classic Mac OS
 */
int mac_vsnprintf(char* str, size_t size, const char* format, va_list ap) {
    
    char temp_buffer[4096]; /* Adjust size as needed */
    int result;
    
    /* If buffer size is 0 or negative, do nothing */
    if (size <= 0) return -1;
    
    /* Use a temporary buffer to avoid overflow */

    result = vsprintf(temp_buffer, format, ap);
    
    /* Copy result to output buffer with size limit */
    if (result >= 0) {
        size_t copy_size = (result < size - 1) ? result : size - 1;
        memcpy(str, temp_buffer, copy_size);
        str[copy_size] = '\0'; /* Ensure null termination */
    } else {
        if (size > 0) str[0] = '\0';
    }
    
    return result;
}

/*
 * Simplified printf implementation
 */
int mac_printf(const char *format, ...) {
    char buffer[4096]; /* Adjust size as needed */
    va_list args;
    int result;
    
    va_start(args, format);
    result = vsprintf(buffer, format, args);
    va_end(args);
    
    /* In a real application, you'd output this to the console or a log */
    /* For now, we'll just return the length */
    
    return result;
}

/*
 * Memory allocation mapped to Mac OS Memory Manager
 */
void* mbedtls_calloc(size_t count, size_t size) {
    unsigned long totalSize;
    totalSize = (unsigned long)(count * size);
    return NewPtrClear(totalSize);
}

void mbedtls_free(void* ptr) {
    if (ptr != NULL)
        DisposePtr((Ptr)ptr);
}