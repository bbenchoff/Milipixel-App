/* 
 * SSLWrapper.h
 * 
 * SSL wrapper interface for Classic Mac OS using PolarSSL/mbedTLS
 */

#ifndef SSL_WRAPPER_H
#define SSL_WRAPPER_H

#include <OpenTransport.h>
#include <OpenTptInternet.h>

/* Include the necessary mbedTLS headers */
#include "ssl.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "error.h"

typedef void (*LoggingCallback)(const char* message);

/* SSL State Structure */
typedef struct {
    EndpointRef              endpoint;      /* OT endpoint for the connection */
    mbedtls_ssl_context      ssl;           /* PolarSSL context */
    mbedtls_ssl_config       conf;          /* PolarSSL configuration */
    mbedtls_entropy_context  entropy;       /* Entropy source for SSL */
    mbedtls_ctr_drbg_context ctr_drbg;      /* Random number generator context */
    int                      initialized;   /* Flag to track initialization */
} SSLState;


/* Function Prototypes */
OSStatus SSL_Initialize(SSLState* state, LoggingCallback logFunc);
OSStatus SSL_Connect(SSLState* state, InetAddress* address, TEHandle responseText, LoggingCallback logFunc);
OSStatus SSL_Send(SSLState* state, const void* buffer, size_t length, size_t* bytesSent, LoggingCallback logFunc);
OSStatus SSL_Receive(SSLState* state, void* buffer, size_t bufferSize, size_t* bytesReceived, LoggingCallback logFunc);
void SSL_Close(SSLState* state);
int mac_entropy_func(void *data, unsigned char *ouput, size_t len);

#endif /* SSL_WRAPPER_H */