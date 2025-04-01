# Milipixel-App

This is a C89/90 pport of MbedTLS for Mac System 7/8/9. It works, it compiles under Metrowerks Codewarrior 4. Here's proof:

![The app running](https://bbenchoff.github.io/images/MacSSL1.png)
 
 This is a basic app that performs a GET request on whatever is in `api.h`, and prints the result out to the text box (with a lot of debug information, of course). The idea of this project was to build an 'app' of sorts for (640by480)[https://640by480.com/], my 'instagram clone for vintage digital cameras'. The idea would be to login, post images, view images, and read comments. I would need HTTPS for that, so here we are: a port of MbedTLS for the classic mac. It supports TLS1.3. Holy crap, it's amazing.

 ## The Problems

 This app does not work. I'm getting handshake errors when trying to connect to the 640by480 API. I've adjusted the TLS down to 1.0 up to 1.3, that doesn't work. I've matched the ciphers available, that doesn't work. There's something _deeper_ here that I'm not getting, __because this app doesn't work__. The MbedTLS compiles and runs, it just doesn't connect.

Mbedtls was written for C99 compilers, but my version of CodeWarrior only supports C89/C90. The transition required significant code modifications:

* Creating compatibility layers for modern C integer types
* Implementing 64-bit integer emulation
* Restructuring code to declare variables at block beginnings (C89 requirement)
* Addressing include path limitations in Mac’s un-*NIX-like file system

The biggest problem? *C89 doesn’t support variadic macros or method overloading*. 64-bit ints are completely unknown on this platform. The mbedtls library uses 64-bit data types. int64_t, uint64_t, and the like. My compiler doesn’t know what those are. So I need to create them. Out of fucking thin air and structs, I guess. All of that is defined in `mac_stdint.h`. I made a shim library that does all of the 64-bit arithmetic, but that also means I need to port the code, and there's a lot of 64-bit math in the crypto libraries.

There's also the entropy problem, but that was solved with:

* System clock and tick counts at microsecond resolution
* Mouse movement tracking
* Memory states and allocation patterns
* Hardware timing variations
* Network packet timing with OTGetTimeStamp()
* TCP sequence numbers and connection statistics
* Time delays between user interactions
* The amount of time it takes for the screensaver to activate

## Current Status

Right now the current state of this port is that portions of MbedTLS compile (not everything, it's just a minimal system), and I SHOULD be getting data from my server, but all I get is SSL handshake failures. Yes, I've tried to reconfigure my server to work with the ciphersuites I have. It didn't work.

Basically I'm looking for another set of eyes on this. Perferably someone who has ported MbedTLS before. I'm sure that with _a little bit of work_, this could be made to pull data from an API. But I'm burnt out and this is what I'm releasing to the world. Somebody take this and fix it.

This github repo is EXACTLY like the folder on my build machine, a Power Mac G3 233MHz, running OS 8.6. Codewarrior Pro 4, obviously. There's also a .sit file that is this folder, because of resource forks and such.

![Box art](/Art/BoxArt.png)