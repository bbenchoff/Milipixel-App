/* 
 * SSLWrapper.c
 * 
 * SSL wrapper implementation for Classic Mac OS using PolarSSL/mbedTLS
 */


#include "Globals.h"
#include "SSLWrapper.h"
#include <string.h>
#include <stdio.h>
#include "api.h"

/* 
 * Custom send/receive functions for PolarSSL that use Open Transport
 */
static int ot_send(void *ctx, const unsigned char *buf, size_t len)
{
    EndpointRef endpoint = (EndpointRef)ctx;
    OTResult result;
    
    result = OTSnd(endpoint, (void*)buf, len, 0);
    
    if (result >= 0)
        return result;
    else
        return -1; /* Return generic error code */
}

static int ot_recv(void *ctx, unsigned char *buf, size_t len)
{
    EndpointRef endpoint = (EndpointRef)ctx;
    OTResult result;
    
    result = OTRcv(endpoint, buf, len, 0);
    
    if (result > 0)
        return result;
    else if (result == 0)
        return 0; /* Connection closed */
    else if (result == kOTNoDataErr)
        return MBEDTLS_ERR_SSL_WANT_READ; /* No data available right now */
    else
        return -1; /* Other error */
}


/* Initialize the SSL state with progressive logging via callback */
OSStatus SSL_Initialize(SSLState* state, LoggingCallback logFunc)
{
    int ret;
    UInt32 ticks;
    char seed_buf[64];
    char errorMsg[100];
    
    /* Set simple cipher suites that are most likely to be compatible */
	const int ciphersuites[] = {
		MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,     /* Common and simple */
		MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,     /* Alternative */
		MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,    /* Very compatible fallback */
		0  /* End of list */
	};
    
    if (state == NULL) {
        if (logFunc) logFunc("Error: NULL state pointer");
        return paramErr;
    }
    
    /* If already initialized, clean up first */
    if (state->initialized) {
        if (logFunc) logFunc("Found existing SSL state, cleaning up...");
        SSL_Close(state);
    }
    
    /* Log start of initialization */
    if (logFunc) logFunc("Starting SSL initialization");
    
    /* Clear the state structure */
    memset(state, 0, sizeof(SSLState));
    
    /* STEP 1: Gather entropy */
    if (logFunc) logFunc("Step 1: Gathering entropy sources");
    
    /* Create a better entropy source using Classic Mac resources */
    ticks = TickCount(); /* Get current tick count from Mac OS */
    
    /* Format info message */
    sprintf(errorMsg, "  System ticks: %lu", (unsigned long)ticks);
    if (logFunc) logFunc(errorMsg);
    
    /* Create a seed buffer with various system data */
    memset(seed_buf, 0, sizeof(seed_buf));
    BlockMoveData(&ticks, seed_buf, sizeof(ticks));
    
    /* Use system time for additional entropy */
    {
        unsigned long dateTime;
        GetDateTime(&dateTime);
        
        /* Format info message */
        sprintf(errorMsg, "  System date/time: %lu", dateTime);
        if (logFunc) logFunc(errorMsg);
        
        BlockMoveData(&dateTime, &seed_buf[4], sizeof(dateTime));
    }
    
    /* Add some additional entropy sources if available */
    if (LMGetCurApName() != NULL) {
        /* Format info message */
        sprintf(errorMsg, "  App name first byte: 0x%02X", (unsigned char)LMGetCurApName()[0]);
        if (logFunc) logFunc(errorMsg);
        
        seed_buf[12] = LMGetCurApName()[0];
    }
    
    /* Fill rest with pseudo-random values */
    {
        int i;
        for (i = 16; i < sizeof(seed_buf); i++) {
            seed_buf[i] = (char)((ticks * i * 0xC13F) & 0xFF);
        }
    }
    if (logFunc) logFunc("  Entropy gathering completed");
    
    /* STEP 2: Initialize entropy context */
    if (logFunc) logFunc("Step 2: Initializing entropy context");
    
    /* Initialize entropy source */
    mbedtls_entropy_init(&state->entropy);
    if (logFunc) logFunc("  Entropy context initialized");
    
    /* STEP 3: Initialize random number generator */
    if (logFunc) logFunc("Step 3: Initializing random number generator");
    
    /* Initialize the RNG context */
    mbedtls_ctr_drbg_init(&state->ctr_drbg);
    if (logFunc) logFunc("  RNG context initialized");
    
    /* STEP 4: Seed the RNG */
    if (logFunc) logFunc("Step 4: Seeding random number generator");
    
    /* Try using a simple personalization string instead of entropy function */
    ret = mbedtls_ctr_drbg_seed(
        &state->ctr_drbg,
        mac_entropy_func, // the custom entropy function
        NULL, // no data needed for custom entropy function
        (const unsigned char *)seed_buf, 
        sizeof(seed_buf)
    );
    
    if (ret != 0) {
        sprintf(errorMsg, "ERROR: RNG seed failed with code %d", ret);
        if (logFunc) logFunc(errorMsg);
        mbedtls_entropy_free(&state->entropy);
        return ret;
    }
    if (logFunc) logFunc("  RNG successfully seeded");
    
    /* STEP 5: Initialize SSL context */
    if (logFunc) logFunc("Step 5: Initializing SSL context");
    
    /* Initialize SSL context */
    mbedtls_ssl_init(&state->ssl);
    if (logFunc) logFunc("  SSL context initialized");
    
    /* STEP 6: Initialize SSL config */
    if (logFunc) logFunc("Step 6: Initializing SSL configuration");
    
    /* Initialize SSL config */
    mbedtls_ssl_config_init(&state->conf);
    if (logFunc) logFunc("  SSL configuration initialized");
    
    /* STEP 7: Set SSL config defaults */
    if (logFunc) logFunc("Step 7: Setting SSL configuration defaults");
    
    /* Set default SSL configuration */
    ret = mbedtls_ssl_config_defaults(
        &state->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    
    if (ret != 0) {
        sprintf(errorMsg, "ERROR: SSL config defaults failed with code %d", ret);
        if (logFunc) logFunc(errorMsg);
        mbedtls_ssl_free(&state->ssl);
        mbedtls_ssl_config_free(&state->conf);
        mbedtls_ctr_drbg_free(&state->ctr_drbg);
        mbedtls_entropy_free(&state->entropy);
        return ret;
    }
    if (logFunc) logFunc("  SSL configuration defaults set");
    
    /* STEP 8: Configure SSL settings */
    if (logFunc) logFunc("Step 8: Configuring SSL settings");
    
    /* Set RNG function */
    mbedtls_ssl_conf_rng(&state->conf, mbedtls_ctr_drbg_random, &state->ctr_drbg);
    if (logFunc) logFunc("  RNG function configured");
    
    /* Skip certificate verification for testing */
    mbedtls_ssl_conf_authmode(&state->conf, MBEDTLS_SSL_VERIFY_NONE);
    if (logFunc) logFunc("  Certificate verification disabled");
    
    /* Set TLS 1.2 for compatability */
    mbedtls_ssl_conf_min_version(&state->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&state->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    if (logFunc) logFunc("  SSL/TLS version set to TLS 1.2");
    
	mbedtls_ssl_conf_ciphersuites(&state->conf, ciphersuites);
	if (logFunc) logFunc("  Cipher suites set to compatible options");

    /* Increase timeout for slow connections */
    mbedtls_ssl_conf_read_timeout(&state->conf, 30000);
    if (logFunc) logFunc("  Read timeout set to 30 seconds");
    
    /* STEP 9: Setup SSL with configuration */
    if (logFunc) logFunc("Step 9: Applying configuration to SSL context");
    
    /* Setup SSL with config */
    ret = mbedtls_ssl_setup(&state->ssl, &state->conf);
    if (ret != 0) {
        sprintf(errorMsg, "ERROR: SSL setup failed with code %d", ret);
        if (logFunc) logFunc(errorMsg);
        mbedtls_ssl_config_free(&state->conf);
        mbedtls_ctr_drbg_free(&state->ctr_drbg);
        mbedtls_entropy_free(&state->entropy);
        return ret;
    }
    if (logFunc) logFunc("  SSL configuration successfully applied");
    
    /* Success! */
    state->initialized = 1;
    state->endpoint = kOTInvalidEndpointRef;
    
    if (logFunc) logFunc("SSL initialization completed successfully!");
    return noErr;
}


/* Create an endpoint for SSL communication */
static OSStatus CreateSecureEndpoint(EndpointRef* endpoint)
{
    OSStatus err;
    
    /* Create an endpoint using TCP protocol */
    *endpoint = OTOpenEndpoint(OTCreateConfiguration(kTCPName), 0, NULL, &err);
    return err;
}

/* Establish an SSL connection to the specified address */
OSStatus SSL_Connect(SSLState* state, InetAddress* address, TEHandle responseText, LoggingCallback logFunc)
{
    OSStatus err;
    OTResult result;
    TBind bindReq;
    TCall sndCall;
    int ret;
    int handshake_attempts;
    char debug_msg[150];
    unsigned char alert_level;
	unsigned char alert_type;
	char msg[100];
    
    if (!state->initialized)
        return paramErr;
    
    /* Create the TCP endpoint */
    err = CreateSecureEndpoint(&state->endpoint);
    if (err != noErr) {
        if(responseText != NULL) {
            sprintf(debug_msg, "Failed to create secure endpoint: %d", (int)err);
            TESetText(debug_msg, strlen(debug_msg), responseText);
            TEUpdate(&(*responseText)->viewRect, responseText);
        }
        return err;
    }
        
    /* Debug output */
    if(responseText != NULL)
    {
        TESetText("Setting up SSL connection...", 26, responseText);
        TEUpdate(&(*responseText)->viewRect, responseText);
    }
    
    /* Bind the endpoint */
    bindReq.addr.maxlen = 0;
    bindReq.addr.len = 0;
    bindReq.addr.buf = NULL;
    bindReq.qlen = 0;
    
    err = OTBind(state->endpoint, &bindReq, NULL);
    if (err != noErr) {
        if(responseText != NULL) {
            sprintf(debug_msg, "Failed to bind endpoint: %d", (int)err);
            TESetText(debug_msg, strlen(debug_msg), responseText);
            TEUpdate(&(*responseText)->viewRect, responseText);
        }
        OTCloseProvider(state->endpoint);
        state->endpoint = kOTInvalidEndpointRef;
        return err;
    }
    
    /* Set up the connection call structure */
    sndCall.addr.maxlen = sizeof(InetAddress);
    sndCall.addr.len = sizeof(InetAddress);
    sndCall.addr.buf = (UInt8*)address;
    
    sndCall.opt.maxlen = 0;
    sndCall.opt.len = 0;
    sndCall.opt.buf = NULL;
    
    sndCall.udata.maxlen = 0;
    sndCall.udata.len = 0;
    sndCall.udata.buf = NULL;
    
    /* Connect to the server */
    if(responseText != NULL)
    {
        TESetText("Establishing TCP connection...", 29, responseText);
        TEUpdate(&(*responseText)->viewRect, responseText);
    }
    
    err = OTConnect(state->endpoint, &sndCall, NULL);
    
    /* Check for asynchronous completion */
    if (err == kOTNoDataErr) {
        if(responseText != NULL)
        {
            TESetText("Waiting for connection completion...", 35, responseText);
            TEUpdate(&(*responseText)->viewRect, responseText);
        }
        
        result = OTLook(state->endpoint);
        
        if (result == T_CONNECT) {
            /* Accept the connection and finish connecting */
            err = OTRcvConnect(state->endpoint, NULL);
            if (err != noErr) {
                if(responseText != NULL) {
                    sprintf(debug_msg, "TCP connection failed during completion: %d", (int)err);
                    TESetText(debug_msg, strlen(debug_msg), responseText);
                    TEUpdate(&(*responseText)->viewRect, responseText);
                }
                OTCloseProvider(state->endpoint);
                state->endpoint = kOTInvalidEndpointRef;
                return err;
            }
        } else {
            if(responseText != NULL) {
                sprintf(debug_msg, "Unexpected connection state: %d", (int)result);
                TESetText(debug_msg, strlen(debug_msg), responseText);
                TEUpdate(&(*responseText)->viewRect, responseText);
            }
            OTCloseProvider(state->endpoint);
            state->endpoint = kOTInvalidEndpointRef;
            return kOTStateChangeErr;
        }
    } else if (err != noErr) {
        if(responseText != NULL) {
            sprintf(debug_msg, "TCP connection failed: %d", (int)err);
            TESetText(debug_msg, strlen(debug_msg), responseText);
            TEUpdate(&(*responseText)->viewRect, responseText);
        }
        OTCloseProvider(state->endpoint);
        state->endpoint = kOTInvalidEndpointRef;
        return err;
    }
    
    /* Debug output */
    if(responseText != NULL)
    {
        TESetText("TCP connection established, starting SSL handshake...", 50, responseText);
        TEUpdate(&(*responseText)->viewRect, responseText);
    }
    
    /* Set the hostname for SNI (Server Name Indication) */
    ret = mbedtls_ssl_set_hostname(&state->ssl, API_HOST);
    if (ret != 0) {
        /* Non-fatal error, continue anyway but log it */
        if(responseText != NULL)
        {
            sprintf(debug_msg, "Warning: SNI hostname setup failed: %d", ret);
            TESetText(debug_msg, strlen(debug_msg), responseText);
            TEUpdate(&(*responseText)->viewRect, responseText);
        }
    }
    
    /* Set up mbedTLS I/O functions to use Open Transport */
    mbedtls_ssl_set_bio(&state->ssl, state->endpoint, ot_send, ot_recv, NULL);
    
    /* Debug output */
    if(responseText != NULL)
    {
        TESetText("Beginning SSL handshake (this may take a moment)...", 49, responseText);
        TEUpdate(&(*responseText)->viewRect, responseText);
    }
    
    /* Perform the SSL handshake with better error reporting */
    handshake_attempts = 0;
    while (1) {
        ret = mbedtls_ssl_handshake(&state->ssl);
        
        if (ret == 0) {
            /* Handshake successful! Break out of the loop */
            break;
        }
        
        /* Check for retriable errors */
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* These are normal during handshake - just try again */
            handshake_attempts++;
            
            /* Show progress periodically */
            if (responseText != NULL && (handshake_attempts % 5 == 0)) {
                char msg[100];
                sprintf(msg, "SSL handshake in progress... (attempt %d)\n", handshake_attempts);
                logFunc(msg);
            }
            
            /* Prevent infinite loops - give up after too many attempts */
            if (handshake_attempts > 100) {
				if (logFunc) logFunc("SSL handshake timeout -- too many attempts\n");
				break;
            }
            
            continue;
        }
        
		if(ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE)
		{
			if(logFunc)
			{
				
				sprintf(msg, "Server sent fatal alert during handshake (code %d)\n", ret);
				logFunc(msg);
				
				// try to get more info about the alert
				alert_level = state->ssl.in_msg[0];
				alert_type = state->ssl.in_msg[1];
				
				sprintf(msg, "Alert leve: %d, type: %d\n", alert_level, alert_type);
				logFunc(msg);
			}
			break;
		}
		
		//Other non-retriable error
		if(logFunc)
		{
			
			sprintf(msg, "SSL handshake fialed with error code: %d\n", ret);
			logFunc(msg);
		}
		break;
		
    }
    
    /* Handshake successful! */
    if(responseText != NULL)
    {
        const char* cipher = mbedtls_ssl_get_ciphersuite(&state->ssl);
        if (cipher != NULL) {
            sprintf(debug_msg, "SSL handshake successful! Connected with %s", cipher);
        } else {
            sprintf(debug_msg, "SSL handshake successful! Connected securely.");
        }
        TESetText(debug_msg, strlen(debug_msg), responseText);
        TEUpdate(&(*responseText)->viewRect, responseText);
    }
    
    return noErr;
}

/* Enhance the SSL_Send function */
OSStatus SSL_Send(SSLState* state, const void* buffer, size_t length, size_t* bytesSent, LoggingCallback logFunc)
{
    int ret;
    size_t total_sent = 0;
    int retries = 0;
    const int max_retries = 10;
    char msg[100];
    
    if (!state->initialized || state->endpoint == kOTInvalidEndpointRef) {
        if (logFunc) logFunc("Error: SSL not initialized or no endpoint");
        *bytesSent = 0;
        return paramErr;
    }
    
    if (logFunc) logFunc("Attempting to send data...");
    
    /* Keep trying until all data is sent or error */
    while (total_sent < length && retries < max_retries) {
        ret = mbedtls_ssl_write(&state->ssl, 
                              (const unsigned char*)buffer + total_sent, 
                              length - total_sent);
        
        if (ret > 0) {
            /* Data sent successfully */
            total_sent += ret;
            
            sprintf(msg, "Sent %d bytes (total: %lu of %lu)", ret, (unsigned long)total_sent, (unsigned long)length);
            if (logFunc) logFunc(msg);
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ) {
            /* Need to wait - retry */
            retries++;
            
            
            sprintf(msg, "SSL write would block (retry %d of %d)", retries, max_retries);
            if (logFunc) logFunc(msg);
            
            continue;
        }
        else {
            /* Error occurred */
            
            sprintf(msg, "SSL write error: %d", ret);
            if (logFunc) logFunc(msg);
            
            *bytesSent = total_sent;
            return ret;
        }
    }
    
    if (total_sent < length) {
        if (logFunc) logFunc("Failed to send all data after maximum retries");
        *bytesSent = total_sent;
        return -1;
    }
    
    *bytesSent = total_sent;
    if (logFunc) logFunc("Data sent successfully");
    return noErr;
}

/* Receive data from the SSL connection with better debugging */
OSStatus SSL_Receive(SSLState* state, void* buffer, size_t bufferSize, size_t* bytesReceived, LoggingCallback logFunc)
{
    int ret;
    char msgBuf[100];
    
    if (!state->initialized || state->endpoint == kOTInvalidEndpointRef) {
        if (logFunc) logFunc("Error: SSL not initialized or no endpoint");
        return paramErr;
    }
    
    /* Try to read data */
    if (logFunc) logFunc("Attempting to read data from server...");
    
    ret = mbedtls_ssl_read(&state->ssl, buffer, bufferSize);
    
    if (ret > 0) {
        /* Data received successfully */
        *bytesReceived = ret;
        sprintf(msgBuf, "Successfully received %d bytes", ret);
        if (logFunc) logFunc(msgBuf);
        return noErr;
    } 
    else if (ret == 0) {
        /* Connection closed by server */
        *bytesReceived = 0;
        if (logFunc) logFunc("Connection closed by server (clean shutdown)");
        return noErr;
    } 
    else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        /* No data available yet - need to wait */
        *bytesReceived = 0;
        if (logFunc) logFunc("No data available yet (WANT_READ) - may need to retry");
        return kOTNoDataErr;
    }
    else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
        /* Read timeout */
        *bytesReceived = 0;
        if (logFunc) logFunc("Read timeout occurred - server took too long to respond");
        return -1;
    }
    else {
        /* Other error occurred */
        *bytesReceived = 0;
        sprintf(msgBuf, "SSL read error: %d", ret);
        if (logFunc) logFunc(msgBuf);
        return ret;
    }
}

/* Close the SSL connection and clean up */
void SSL_Close(SSLState* state)
{
    if (state == NULL || !state->initialized)
        return;
    
    /* Close the SSL connection with proper notification */
    if (state->endpoint != kOTInvalidEndpointRef) {
        /* Only try to send close_notify if we have a valid endpoint */
        mbedtls_ssl_close_notify(&state->ssl);
        
        /* Close the endpoint */
        OTCloseProvider(state->endpoint);
        state->endpoint = kOTInvalidEndpointRef;
    }
    
    /* Free SSL resources */
    mbedtls_ssl_free(&state->ssl);
    mbedtls_ssl_config_free(&state->conf);
    mbedtls_ctr_drbg_free(&state->ctr_drbg);
    mbedtls_entropy_free(&state->entropy);
    
    state->initialized = 0;
}


/* custom entropy function for Classic Mac OS */
int mac_entropy_func(void *data, unsigned char *output, size_t len)
{
	UInt32 ticks, current_time;
	size_t i;
	
	// The various system values as entropy sources
	ticks = TickCount();
	GetDateTime((unsigned long*)&current_time);
	
	// Fill the output buffer
	for(i = 0 ; i < len ; i++)
	{
		// mix various sources of 'randomness'
		output[i] = (unsigned char)(
			((ticks + i) ^ (current_time >> (i %32 ))) +
			(LMGetCurApName() ? LMGetCurApName()[i%32] : 0) +
			(i * 0x1B)
		);
		
		// change the time and tick values for the next iteration
		ticks = (ticks * 31421 + 6927) % 0x10000;
		current_time = (current_time * 16807) % 0x7FFFFFFF;
	}
	
	return 0; //success	
}