/* Globals.h - only declarations, no initialization */
#ifndef GLOBALS_H
#define GLOBALS_H

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#include "SSLWrapper.h"
#include "api.h"

/* Constants */
#define kControlButtonPart 10  // Part code for a button control
#define kFontIDGeneva 3

/* Protocol Type */
typedef enum {
    kProtocolHTTP,
    kProtocolHTTPS
} ProtocolType;

/* Global variables declarations */
extern char requestBuffer[1024];
extern WindowPtr gMainWindow;
extern ControlHandle gConnectButton;
extern MenuHandle gFileMenu;
extern EndpointRef gTCPEndpoint;
extern InetSvcRef gInetService;
extern char gResponseBuffer[MAX_RESPONSE_SIZE];
extern TEHandle gResponseText;
extern ControlHandle gProtocolRadio[2];  /* Radio buttons for HTTP/HTTPS selection */
extern SSLState gSSLState;
extern ProtocolType gProtocolType;

#endif