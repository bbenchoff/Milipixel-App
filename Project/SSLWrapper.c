/* 
 * SSLWrapper.c
 * 
 * SSL wrapper implementation for Classic Mac OS using PolarSSL/mbedTLS
 */


#include "Globals.h"
#include "SSLWrapper.h"
#include <string.h>
#include <stdio.h>
#include <LowMem.h>
#include <Resources.h>
#include <Processes.h>
#include <Folders.h>
#include <Files.h>
#include <Gestalt.h>
#include "api.h"
#include "debug.h"

const char *root_ca = 
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
    "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
    "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\n"
    "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\n"
    "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n"
    "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\n"
    "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\n"
    "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\n"
    "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\n"
    "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\n"
    "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\n"
    "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n"
    "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\n"
    "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\n"
    "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\n"
    "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\n"
    "-----END CERTIFICATE-----\n";

#ifdef __powerc
asm unsigned long GetPPC601Timer(void)
{
	mfspr r3, 5
	blr
}

asm unsigned long GetPPC603PlusTimer(void)
{
	mftb r3
	blr
}
#endif

/* Get the PowerPC timebase register - returns lower 32 bits */
static unsigned long GetPPCTimer(bool is601)
{
#ifdef __powerc
	if(is601)
		return GetPPC601Timer();
	else
		return GetPPC603PlusTimer();
#else
    /* For 68K, use Microseconds() */
    UnsignedWide usec;
    Microseconds(&usec);
    return usec.lo;
#endif
}

/* Get time base resolution - ticks per millisecond */
static double GetTimeBaseResolution(void)
{
    long speed;
    
    /* Try to get processor clock speed */
    if (Gestalt(gestaltProcClkSpeed, &speed) != noErr)
        return 6000.0; /* Default for 60MHz PowerPC */
        
    /* Assume 10 cycles per timebase tick as per PowerPC spec */
    return speed / 1.0e4;
}

/* Fill buffer with enhanced entropy from Mac-specific sources */
int mac_entropy_gather(unsigned char *output, size_t len)
{
    size_t pos = 0;
    static UInt32 entropy_counter = 0;
    double timebase_ticks_per_msec;
    bool is_powerpc = false;
    bool is_601 = false;
    long cpu_type;
    unsigned long disk_data[8];
    ProcessSerialNumber psn;
    ProcessInfoRec process_info;
    Point mouse_point;
    size_t i;
    
    /* Determine CPU type for timebase access method */
    if (Gestalt(gestaltNativeCPUtype, &cpu_type) == noErr) {
        is_powerpc = (cpu_type >= gestaltCPU601);
        is_601 = (cpu_type == gestaltCPU601);
    }
    
    /* Get timebase resolution */
    timebase_ticks_per_msec = GetTimeBaseResolution();
    
    /* Increment our own counter each time we're called */
    entropy_counter++;

    /* Gather initial entropy sources in small discrete chunks */
    while (pos < len) {
        UInt32 block[4];
        size_t block_size = sizeof(block);
        
        /* Only use as much as we need for the final block */
        if (pos + block_size > len)
            block_size = len - pos;
            
        /* 1. System timer with high precision */
        block[0] = GetPPCTimer(is_601);
        
        /* 2. Various time sources that have different resolutions */
        block[1] = TickCount();
        GetDateTime(&block[2]);
        
        /* 3. Mouse location and low-memory globals */
        mouse_point = LMGetMouseLocation();
        block[3] = (UInt32)((mouse_point.h << 16) | (mouse_point.v & 0xFFFF));;
        block[3] ^= (UInt32)LMGetCurApName();
        block[3] ^= (UInt32)LMGetScrnBase();
        
        /* 4. Mix in the entropy counter */
        for (i = 0; i < 4; i++) {
            block[i] ^= entropy_counter * (0x1f1f1f1f + i);
        }
        
        /* Copy this block to the output */
        memcpy(output + pos, block, block_size);
        pos += block_size;
        
        /* Change entropy_counter to ensure different blocks */
        entropy_counter = (entropy_counter * 1103515245 + 12345) & 0x7fffffff;
    }
    
    /* Now, do a second pass to gather even more system state 
       and mix it with what we already have */
       
    /* Get startup volume information */
    {
        short vRefNum;
        long dirID;
        XVolumeParam pb;
        OSErr err;
        
        /* Try to get information about the startup disk */
        FindFolder(kOnSystemDisk, kSystemFolderType, kDontCreateFolder,
                  &vRefNum, &dirID);
        pb.ioVRefNum = vRefNum;
        pb.ioCompletion = 0;
        pb.ioNamePtr = 0;
        pb.ioVolIndex = 0;
        //err = PBXGetVolInfoSync(&pb);
        
        /*
        WE'RE GOING TO HAVE TO FIX THIS
        THIS SHOULD BE VOLUME INFO NOT TICKCOUNT AND RANDOM
        */
        
        if (err == noErr) {
            /* Use volume information for entropy */
            disk_data[0] = TickCount();
            disk_data[1] = Random();
            disk_data[2] = LMGetTicks();
            disk_data[3] = (UInt32)CurResFile();
        }
    }
    
    /* Get information about the current process */
    {
        process_info.processInfoLength = sizeof(ProcessInfoRec);
        process_info.processName = nil;
        process_info.processAppSpec = nil;
        
        GetCurrentProcess(&psn);
        GetProcessInformation(&psn, &process_info);
        
        disk_data[4] = process_info.processSize;
        disk_data[5] = process_info.processMode;
        disk_data[6] = (UInt32)(long)process_info.processLocation;
        disk_data[7] = process_info.processFreeMem;
    }
    
    /* Mix the additional entropy into our output buffer */
    for (i = 0; i < len; i++) {
        output[i] ^= ((unsigned char*)disk_data)[i % sizeof(disk_data)];
    }
    
    /* Add a final non-linear transformation */
    for (i = 0; i < len; i++) {
        /* Apply an S-box like transformation */
        unsigned char b = output[i];
        b = ((b << 1) | (b >> 7)) ^ ((b << 2) | (b >> 6));
        output[i] = b ^ (entropy_counter & 0xFF);
        entropy_counter = (entropy_counter * 214013 + 2531011) & 0x7fffffff;
    }

    return 0; /* Success */
}

/* Custom entropy function for mbedTLS */
int mac_entropy_func(void *data, unsigned char *output, size_t len)
{
    /* Call our enhanced entropy gathering function */
    return mac_entropy_gather(output, len);
}

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
    unsigned char enhanced_seed[128];
    mbedtls_x509_crt ca_cert;
    UInt32 fallback_seed[8];
    Point mouse_point;
        
    /* Set simple cipher suites that are most likely to be compatible */
	const int ciphersuites[] = {
		/* Start with ECDHE ciphers */
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
		MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,	
		
		/* Include basic RSA ciphers for fallback */
		MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,     /* Common and simple */
		MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,     /* Alternative */
		
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
    
    /* STEP 4: Seed the RNG with enhanced entropy sources */
    if (logFunc) logFunc("Step 4: Seeding random number generator with enhanced entropy");
    
    
    /* Fill the buffer with entropy from our custom gatherer */
    mac_entropy_gather(enhanced_seed, sizeof(enhanced_seed));
    
    /* Log the first few bytes for debugging */
    if (logFunc) {
        char seed_debug[100];
        sprintf(seed_debug, "  Seed preview: %02X %02X %02X %02X %02X %02X %02X %02X",
            enhanced_seed[0], enhanced_seed[1], enhanced_seed[2], enhanced_seed[3],
            enhanced_seed[4], enhanced_seed[5], enhanced_seed[6], enhanced_seed[7]);
        logFunc(seed_debug);
    }
    
    /* Try seeding with our custom entropy function */
    ret = mbedtls_ctr_drbg_seed(
        &state->ctr_drbg,
        mac_entropy_func,       /* Use our custom entropy function */
        NULL,                   /* No context needed */
        enhanced_seed,          /* Additional seed data */
        sizeof(enhanced_seed)   /* Size of additional seed */
    );
    
    if (ret != 0) {
        /* If that fails, try a deterministic approach for testing ONLY */
        if (logFunc) {
            sprintf(errorMsg, "RNG seed failed (code %d). Trying fallback method...", ret);
            logFunc(errorMsg);
        }
        
        /* Use a mix of system values as a fallback seed */
        mouse_point = LMGetMouseLocation();
        fallback_seed[0] = TickCount();
        GetDateTime((unsigned long*)&fallback_seed[1]);
        fallback_seed[2] = (UInt32)((mouse_point.h <<16) | (mouse_point.v & 0xFFFF));
        fallback_seed[3] = (UInt32)CurResFile();
        fallback_seed[4] = (UInt32)LMGetCurApName();
        fallback_seed[5] = (UInt32)LMGetApFontID();
        
        /* Try the fallback approach */
        if (logFunc) logFunc("  Using fallback seeding method");
        
        ret = mbedtls_ctr_drbg_seed(
            &state->ctr_drbg,
            mbedtls_entropy_func,    /* Standard function */
            &state->entropy,         /* With our entropy context */
            (unsigned char*)fallback_seed,
            sizeof(fallback_seed)
        );
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
    
    /* we're getting rid of the entire CA loading section
    
	mbedtls_x509_crt_init(&ca_cert);
	ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char *)root_ca, strlen(root_ca) + 1);
	if (ret != 0) {
	    if (logFunc) logFunc("Failed to parse root CA certificate");
	} else {
	    mbedtls_ssl_conf_ca_chain(&state->conf, &ca_cert, NULL);
	    if (logFunc) logFunc("Root CA certificate loaded");
	}
	
	*/
	
	/* Set debug threshold (0-5, higher = more verbose */
    mbedtls_debug_set_threshold(5);
    
    /* Set up debug callback */
    mbedtls_ssl_conf_dbg(&state->conf, ssl_debug_callback, logFunc);
    
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
    mbedtls_ssl_conf_min_version(&state->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    mbedtls_ssl_conf_max_version(&state->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    if (logFunc) logFunc("  SSL/TLS version TLS 1.0-1.2");
    
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
    
    /* Setup the debug */
    /*#ifdef MBEDTLS_DEBUG_C
    	mbedtls_debug_set_threshold(4);
    	mbedtls_ssl_conf_dbg(&state->conf, ssl_debug_callback, logfunc);
    	if(logFunc) logFunc("SSL debug logging enabled at level 4");
    #endif*/
    
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
	char errMsg[100];
	UInt32 delayStart;
	char* alert_desc = "Unknown";
	const char* cipher;
	const char* ver;
    
    if (!state->initialized)
        return paramErr;
    
    /* Create the TCP endpoint */
    err = CreateSecureEndpoint(&state->endpoint);
    if (err != noErr) {
        if(responseText != NULL) {
            sprintf(debug_msg, "Failed to create secure endpoint: %d", (int)err);
            if(logFunc) logFunc(debug_msg);
        }
        return err;
    }
        
    /* Debug output */
    if(responseText != NULL)
    {
        if(logFunc) logFunc("Setting up SSL connection...");
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
            if(logFunc) logFunc(debug_msg);
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
        if(logFunc) logFunc("Establishing TCP connection...");
    }
    
    err = OTConnect(state->endpoint, &sndCall, NULL);
    
    /* Check for asynchronous completion */
    if (err == kOTNoDataErr) {
        if(responseText != NULL)
        {
            if(logFunc) logFunc("Waiting for connection completion...");
        }
        
        result = OTLook(state->endpoint);
        
        if (result == T_CONNECT) {
            /* Accept the connection and finish connecting */
            err = OTRcvConnect(state->endpoint, NULL);
            if (err != noErr) {
                if(responseText != NULL) {
                    sprintf(debug_msg, "TCP connection failed during completion: %d", (int)err);
                    if(logFunc) logFunc(debug_msg);
                }
                OTCloseProvider(state->endpoint);
                state->endpoint = kOTInvalidEndpointRef;
                return err;
            }
        } else {
            if(responseText != NULL) {
                sprintf(debug_msg, "Unexpected connection state: %d", (int)result);
                if(logFunc) logFunc(debug_msg);
            }
            OTCloseProvider(state->endpoint);
            state->endpoint = kOTInvalidEndpointRef;
            return kOTStateChangeErr;
        }
    } else if (err != noErr) {
        if(responseText != NULL) {
            sprintf(debug_msg, "TCP connection failed: %d", (int)err);
            if(logFunc) logFunc(debug_msg);
        }
        OTCloseProvider(state->endpoint);
        state->endpoint = kOTInvalidEndpointRef;
        return err;
    }
    
    /* Debug output */
    if(responseText != NULL)
    {
        if(logFunc) logFunc("TCP connection established, starting SSL handshake...");
    }
    
    /* Set the hostname for SNI (Server Name Indication) */
    ret = mbedtls_ssl_set_hostname(&state->ssl, API_HOST);
    if (ret != 0) {
        /* Non-fatal error, continue anyway but log it */
        if(responseText != NULL)
        {
            sprintf(debug_msg, "Warning: SNI hostname setup failed: %d", ret);
            if(logFunc) logFunc(debug_msg);
        }
    }
    
    /* Log hostname */
    if(logFunc)
    {
    	sprintf(debug_msg, "Using hostname for SNI: %s", API_HOST);
    	logFunc(debug_msg);
    }
    
    /* Set up mbedTLS I/O functions to use Open Transport */
    mbedtls_ssl_set_bio(&state->ssl, state->endpoint, ot_send, ot_recv, NULL);
    
    /* Debug output */
    if(responseText != NULL)
    {
        if(logFunc) logFunc("Beginning SSL handshake (this may take a moment)...");
    }
    
    /* explicit certificicate verificiation */
    //mbedtls_ssl_conf_cert_profile(&state->conf, &mbedtls_x509_crt_profile_none);
    //if(logFunc) logFunc(" Using no certs1");
    
    //mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&state->conf, ssl_debug_callback, logFunc);
    
    
    /* Perform the SSL handshake with better error reporting */
    handshake_attempts = 0;
	
	while (1) {
    	ret = mbedtls_ssl_handshake(&state->ssl);
    	
    	Delay(1, NULL);  //Delay for 1/60th of a second for reasons
      
    	if (ret == 0) {
        	/* Success! Get and show cipher */
        	cipher = mbedtls_ssl_get_ciphersuite(&state->ssl);
        	if(cipher != NULL) {
            	sprintf(debug_msg, "SSL handshake successful! Connected with %s", cipher);
            	if(logFunc) logFunc(debug_msg);
            	ver = mbedtls_ssl_get_version(&state->ssl);
            	sprintf(debug_msg, "Connected using TLS version: %s", ver ? ver : "unknown");
            	if(logFunc) logFunc(debug_msg);
            	return noErr;  /* Return immediately on success */
        	} else {
            	/* Cipher is NULL despite successful return -- shouldn't happen */
            	if(logFunc) logFunc("Handshake appears successful but no cipher negotiated");
            	return -1;  /* Return error if no cipher */
        	}
    	}
    
    	/* Log the error */
    	sprintf(errMsg, "Handshake step returned: %d (0x%x)", ret, ret);
    	if(logFunc) logFunc(errMsg);
    
    	/* Check for retriable errors */
    	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        	/* These are normal during handshake - try again */
        	handshake_attempts++;
        
        	/* Show progress periodically */
        	if (responseText != NULL && (handshake_attempts % 5 == 0)) {
            	sprintf(msg, "SSL handshake in progress... (attempt %d)", handshake_attempts);
            	logFunc(msg);
        	}
        
        	/* Prevent infinite loops */
        	if (handshake_attempts > 100) {
            	if (logFunc) logFunc("SSL handshake timeout -- too many attempts");
            	return -1;
        	}
        
        	continue;
    	}
    
    	/* Handle fatal alerts */
    	if(ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) {
        	if(logFunc) {
           	 sprintf(msg, "Server sent fatal alert during handshake code %d", ret);
            	logFunc(msg);
            
            	/* Try to get more info about the alert */
            	alert_level = state->ssl.in_msg[0];
            	alert_type = state->ssl.in_msg[1];
            
            	switch(alert_type) {
                	case 40: alert_desc = "handshake failure"; break;
                	case 42: alert_desc = "bad certificate"; break;
                	case 43: alert_desc = "unsupported cert"; break;
                	case 47: alert_desc = "illegal param"; break;
                	case 51: alert_desc = "no renegotation"; break;
                	case 70: alert_desc = "protocol version"; break;
                	case 71: alert_desc = "insufficient security"; break;
      	      }
            
    	        sprintf(msg, "Alert level: %d, type %d (%s)", alert_level, alert_type, alert_desc);
    	        logFunc(msg);
     	   }
    	}
    
    	/* Other non-retriable error */
    	if(logFunc) {
    	    sprintf(msg, "SSL handshake failed with error code: %d", ret);
    	    logFunc(msg);
    	}
    
    	/* Return the error code */
    	return ret;
	}
}

/* Enhance the SSL_Send function */
OSStatus SSL_Send(SSLState* state, const void* buffer, size_t length, size_t* bytesSent, LoggingCallback logFunc)
{
    int ret;
    size_t total_sent = 0;
    int retries = 0;
    const int max_retries = 10;
    char msg[100];
    char error_buf[100];
    
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
            sprintf(msg, "SSL write error: %d (0x%08x)", ret, (unsigned int)ret);
            if (logFunc) logFunc(msg);
            
            /* Add specific error code checks */
            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            	if (logFunc) logFunc(" ERROR: connection closed by peer");
            else if(ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            	if (logFunc) logFunc(" ERROR: Write operation would block");
            else if(ret == -0x6880)
            	if (logFunc) logFunc(" ERROR: Read operation would block");
            else if(ret == MBEDTLS_ERR_SSL_TIMEOUT)
            	if (logFunc) logFunc(" ERROR: Timeout");
            else if(ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA)
            	if (logFunc) logFunc(" Error: Bad input parameters");
            
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

/* Receive data with internal retry loop and endpoint state checking */
OSStatus SSL_Receive(SSLState* state, void* buffer, size_t bufferSize, size_t* bytesReceived, LoggingCallback logFunc)
{
    int ret;
    char msgBuf[100];
    int max_retries = 30;  /* Adjust based on your needs */
    int retry_count = 0;
    OTResult endpoint_state;
    
    if (!state->initialized || state->endpoint == kOTInvalidEndpointRef) {
        if (logFunc) logFunc("Error: SSL not initialized or no endpoint");
        return paramErr;
    }
    
    /* Check endpoint state before attempting to receive */
    endpoint_state = OTGetEndpointState(state->endpoint);
    sprintf(msgBuf, "Endpoint state: %d", (int)endpoint_state);
    if (logFunc) logFunc(msgBuf);
    
    /* Only proceed if endpoint is in data transfer state (T_DATAXFER is typically 5) */
    if (endpoint_state != T_DATAXFER) {
        if (logFunc) logFunc("Error: Endpoint not in data transfer state");
        *bytesReceived = 0;
        return -1;
    }
    
    /* Try to read data with retries */
    if (logFunc) logFunc("Attempting to read data from server...");
    
    while (retry_count < max_retries) {
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
            /* No data available yet - retry after a short delay */
            retry_count++;
            
            if (retry_count % 5 == 0 && logFunc) {
                sprintf(msgBuf, "Waiting for data (retry %d of %d)...", retry_count, max_retries);
                logFunc(msgBuf);
                
                /* Check endpoint state again during retries */
                endpoint_state = OTGetEndpointState(state->endpoint);
                sprintf(msgBuf, "Endpoint state during retry: %d", (int)endpoint_state);
                logFunc(msgBuf);
                
                if (endpoint_state != T_DATAXFER) {
                    if (logFunc) logFunc("Error: Endpoint no longer in data transfer state");
                    *bytesReceived = 0;
                    return -1;
                }
            }
            
            /* Give the server some time to send data */
            Delay(1, NULL);  /* 1/60th of a second */
            continue;
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
            sprintf(msgBuf, "SSL read error: %d (0x%08x)", ret, (unsigned int)ret);
            if (logFunc) logFunc(msgBuf);
            return ret;
        }
    }
    
    /* If we get here, we've exhausted our retries */
    if (logFunc) logFunc("Timeout waiting for data from server");
    *bytesReceived = 0;
    return -1;
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

/* Callback function to route debug messages to logFunc */
static void ssl_debug_callback(void *ctx, int level, const char *file, int line, const char *str)
{	
	char main_debug_msg[200];

	LoggingCallback logFunc = (LoggingCallback)ctx;
	
	if(logFunc)
	{
		sprintf(main_debug_msg, "SSL DBG [%d] %s", level, str);
		logFunc(main_debug_msg);
	}
}
