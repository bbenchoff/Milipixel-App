# Milipixel-App

_Note: this repository is not what you want if you want an example of Mbed-TLS on the classic Mac. [MacSSL](https://github.com/bbenchoff/MacSSL) is the repository that contains the example/demo code for Mbed-TLS on Mac System 7/8/9_

This is a client for [Millipixel](https://640by480.com/), an online photo sharing website for vintage digital cameras. It runs on classic Mac hardware:

### Minimum Requirements
* Macintosh computer with 68020 or greater CPU
* System 7 operating system
* Open Transport 1.1.2 
* 4 Megabytes of free memory
* Network connection to the World Wide Web

![Box art](/Art/BoxArt.png)

## Current Status

![The app running](https://bbenchoff.github.io/images/640by480Client.png)

Right now the current state of this application is a test program for the Mbed-TLS library. This works with TSL 1.1, sufficient for my purposes


## Technical details
 
The foundation of this app is [MacSSL](https://github.com/bbenchoff/MacSSL), a port of PolarSSL (Mbed-TLS predecessor) for classic Mac OS 7/8/9. This provides for the necessary SSL/TLS libraries to connect to an HTTPS server.

The JPEG format was released in 1992, and I'm targeting an operating system written in 1991. This is a problem I'm solving with [Aaron Giles' JPEGView application](https://github.com/aaronsgiles/JPEGView). This was a postcardware utility developed for the Macintosh around 1994 allowing computers to open JPEG files. JPEGView was built on the [IJG Library](https://en.wikipedia.org/wiki/Libjpeg), and there are supposed to be native Mac sources for this library, but JPEGView is easier to integrate into this project.

Other than that, the entire project is written in Codewarrior Pro 4, compiled natively on a Power Macintosh G3 desktop running OS 8.6. It's packaged as a FAT application allowing for native code on both 68k and PPC platforms.