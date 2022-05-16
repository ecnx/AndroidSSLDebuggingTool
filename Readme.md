Android SSL Debugging Tool
--------------------------

See also for HTTP2 offline analysis: https://github.com/ecnx/h2dump

Note: Root required, be careful not to brick your phone! Make backup.  
Note: This method fails on some phone models, be prepared it might crash.  
Note: I take no responsibility of any damage made to phone accidenyaly.  
Note: Check if you need some kind of permission to debug 3rd party APK  

**What to debug exactly?**  
Most of Android applications will use OpenSSL library embedded  
into Android phone to communicate over network via SSL/TLS protocol.  
OpenSSL library usually is located in .so files:
* /system/lib/libcrypto.so
* /system/lib/libssl.so

Usually an Android application to communicate over SSL/TLS would use:
* SSL_read
* SSL_write

**How does it work?**  
Hooking up these two functions should provide plaintext data.  
Stock rom library can be renamed and newly created library  
can be put instead of it with exact symbol (e.g. function) names.  
This newly added, intermediate library will hook up some data,  
then the renamed stock rom library will be used, to make everything work.  
This solution is not limited to SSL/TLS traffic debugging,  
can be used as well to debug RSA key generation or calculating SHA-1, etc...  

**Modification process**  
Change package_of_your_app to package of your app in all files having it.  

Install some tools:
* ndk with cland, Android C/C++ cross compiler
* bbe, binary file substiture utility
* adb, for transfering file from or to the phone

Some another projects here will be needed:
 * symrename, needed to build intermediate library
 * elfcrack, needed to build intermediate library
 * h2dump, HTTP/2.0 traffic analysis tool
 
Create intermediate library:
* pull /system/lib/libssl.so from phone with adb into ./sys/libssl.so
* use ./mkdict, it will generate symbol rename table, ./dict
* then use ./mkfunc, it will make function forwarding source, ./src/func.c
* hook functions you are interested in
* run make build, interested library will be put into ./libssl.so

Install modifications:
* make sure you have backup of your phone system, data and everything
* make sure you know how to restore this backup and tested restoring it
* do not touch /system/lib/libcrypto.so, until you debug RSA, hashing, etc
* rename /system/lib/libssl.so to /system/lib/libSSL.so 
* put intermediate library /system/lib/libssl.so
* reboot the phone
* start your app to some tasks on it
* log with SSL/TLS traffic should appear at /data/data/package_of_your_app/files/log
* analyse log file with h2dump

Sometimes apps do not use or use their OpenSSL shipped in APK, then it won't work.

**Hooking example**  
```
void* SSL_write(void* a, void* b, void* c) {
    void* x = ((void* (*) (void*, void*, void*)) func_addr[8])(a, b, c);
    int fd = ((int (*) (void*)) func_addr[146])(a);
    if ((int) x > 0) {
        log_binary('W', fd, b, (int) x);
    }
    return x;
}

void* SSL_read(void* a, void* b, void* c) {
    void* x = ((void* (*) (void*, void*, void*)) func_addr[5])(a, b, c);
    int fd = ((int (*) (void*)) func_addr[146])(a);
    if ((int) x > 0) {
        log_binary('R', fd, b, (int) x);
    }
    return x;
}
```
*Where 8, 5 and 146 are taken from generated ./src/func-list.h*
