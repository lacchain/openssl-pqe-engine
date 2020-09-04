
# IBRand Playbook
Created: JGilmore (23/06/2020 20:18)

## A. Overview
IronBridge IBRand engine is an openssl RNG plugin that allows random data to be acquired from CQC IronBridge API rather than from conventional sources.
OpenSSL *engines* are now a standard feature of OpenSSL which allow support for additional features without having to modify, or indeed even rebuild, openssl itself.

## B. Credits
Much of this code has been derived from the excellent infnoise engine from Thomás Inskip.
```
// Copyright 2018 Thomás Inskip. All rights reserved.
// https://github.com/tinskip/infnoise-openssl-engine
//
// Implementation of OpenSSL RAND engine which uses the infnoise TRNG to
// generate true random numbers: https://github.com/waywardgeek/infnoise
//

```
* git clone https://github.com/13-37-org/infnoise
* git clone https://github.com/tinskip/infnoise-openssl.git

Changes to the above two modules have been made to also support the IronBridge RNG API.  These changes respect and are in accordance with the licenses of the respective original components, and as such are available on request.
Please find contact details at http://www.cambridgequantum.com


## C. Playbook

### C1. Install some tools, utilities and libs
* ***Good practice***
  * sudo apt update
  * sudo apt upgrade
* ***Devtools (if not already present)***
  * sudo apt install gcc perl make
  * sudo apt install git
  * sudo apt install net-tools
  * sudo apt install vim
* ***Required***
  * sudo apt install openssl
  * sudo apt install openssl-dev
  * sudo apt-get install libssl-dev
  * sudo apt-get install libftdi-dev

### C2. Get, Build and install OpenSSL [Optional]
This product requires a version of OpenSSL that has engine support.
This can be tested with the "openssl engine" command:
#### Check if Openssl has engine support
   Requesting a list of available engines will typically include the following...
   ```
   $ openssl engine
   (rdrand) Intel RDRAND engine
   (dynamic) Dynamic engine loading support
   $
   ```
   If not, you may need to build and install the latest version of openssl yourself, as follows...

#### Build and install openssl
  * cd $(PROJECT_DEV_FOLDER)
  * git clone https://github.com/openssl/openssl
  * pushd openssl/
  * ./config
  * make
  * sudo make install
  * popd

### C3. Get, Build and Install IBRand Engine

#### Get project
In a your normal, or a convenient, dev folder (e.g. */home/someuser/dev/* )...
* git clone https://gitlab.cqc.local/jgilmore/ironbridge.software.ib_openssl.git  (or similar)
* cd ironbridge.software.ib_openssl

Several of the commands below refer to the ibrand development directory. This is represented throughtout as $(PROJECT_DEV_FOLDER) for which the following export is required:
* export PROJECT_DEV_FOLDER=/home/someuser/dev/ironbridge.software.ib_openssl

#### Component: ibrand_openssl
**"ibrand_openssl"** is the IronBridge IBRand openssl engine (plugin)
  * Build
    * pushd ibrand_openssl
    * make
    * popd
* Deploy
  * sudo cp ./ibrand_openssl/ibrand_openssl.so /usr/local/lib/engines-3/
  * sudo cp ./ibrand_openssl/ibrand_openssl.so /usr/lib/x86_64-linux-gnu/engines-1.1/
* Verify
  * ls -al ./ibrand_openssl/ibrand_openssl.so
    Expect something like:
    ```
    -rwxrwxr-x 1 someuser someuser 13072 Jun 23 18:17 ibrand_openssl.so
    ```
  * ls -al /usr/local/lib/engines-3/
  * ls -al /usr/lib/x86_64-linux-gnu/engines-1.1/
  Expect both to include ibrand_openssl.so:
  ```
  -rwxr-xr-x 1 root root 24520 Jun 19 00:15 afalg.so
  -rwxr-xr-x 1 root root  7480 Jun 19 00:15 capi.so
  -rwxr-xr-x 1 root root 13072 Jun 23 18:19 ibrand_openssl.so                   <=== NB
  -rwxr-xr-x 1 root root 28864 Jun 19 00:15 padlock.so
  ```
#### Component: ibrand_lib
**"ibrand_lib"** is an internal dynamic library used by ***ibrand_openssl*** at runtime.
* Build
  * pushd ibrand_lib/software
  * sudo make -f Makefile.linux install-lib
  * popd
* Deploy
  * Nothing to do - it is done by the makefile
* Verify
  * ls -al ./ibrand_lib/software/libibrand.so
    Expect something like:
    ```
    -rwxr-xr-x 1 root root 33328 Jun 23 19:01 libibrand.so
    ```
  * ls -al /usr/local/lib/
    Expect it to include:
    ```
    drwxr-xr-x  2 root root     4096 Jun 23 18:19 engines-3
    -rw-r--r--  1 root root  8381934 Jun 19 00:15 libcrypto.a
    lrwxrwxrwx  1 root root       14 Jun 19 00:15 libcrypto.so -> libcrypto.so.3
    -rwxr-xr-x  1 root root  4672968 Jun 19 00:15 libcrypto.so.3
    -rw-r--r--  1 root root    33328 Jun 23 19:01 libibrand.so                  <=== NB
    -rw-r--r--  1 root root  1093154 Jun 19 00:15 libssl.a
    lrwxrwxrwx  1 root root       11 Jun 19 00:15 libssl.so -> libssl.so.3
    -rwxr-xr-x  1 root root   704576 Jun 19 00:15 libssl.so.3
    ```
  * ls -al /usr/local/include/
    Expect it to include:
    ```
    -rw-r--r--  1 root root 2897 Jun 23 19:24 libibrand.h                       <=== NB
    drwxr-xr-x  2 root root 4096 Jun 19 00:15 openssl
    ```

### C4. Configuration
#### OPENSSL_CONF
* ls -al /home/someuser/dev/ironbridge.software.ib_openssl/ibrand_openssl/ibrand_openssl.cnf
  Expect something like:
  ```
  -rwxr--r-- 1 someuser someuser 259 Jun 23 17:59 /home/someuser/dev/ironbridge.software.ib_openssl/ibrand_openssl/ibrand_openssl.cnf
  ```
* export OPENSSL_CONF="$(PROJECT_DEV_FOLDER)/ibrand_openssl/ibrand_openssl.cnf"
  e.g.
  ```
  export OPENSSL_CONF="/home/someuser/dev/ironbridge.software.ib_openssl/ibrand_openssl/ibrand_openssl.cnf"
  ```
#### IBRAND_CONF
This is the IronBridge/IBRand configuration file.
* export IBRAND_CONF="$(PROJECT_DEV_FOLDER)/ibrand.cnf"
  e.g.
  ```
  export IBRAND_CONF="/home/someuser/dev/ironbridge.software.ib_openssl/ibrand.cnf"
  ```

### C5. Test Data
The IBRand openssl engine acquires entropy from a local cache, which is populated by a separate service.  The location and type of this cache is specified in the config file *ibrand.cnf* mentioned above in the IBRAND_CONF section.
This section shows how to create some recognisable dummy data for testing and verification purposes.

* sudo mkdir /var/lib/ibrand
* sudo cp ./ibrand_data.bin /var/lib/ibrand/
* ls -al /var/lib/ibrand/
  Expect something like:
  ```
  -rwxr--r--  1 someuser someuser 3600 Jun 23 19:38 ibrand_data.bin
  ```
This file contains repeated blocks of text...
```
DUMMY DATA FROM ibrand_data.bin.        
----+----1----+----2----+----3--        
[CQC-IronBridge][CQC-IronBridge]        
----+----1----+----2----+----3--        
Cambridge Quantum Computing Ltd.        
----+----1----+----2----+----3--        
```
...encoded in Base64...
```
RFVNTVkgREFUQSBGUk9NIGlicmFuZF9kYXRhLmJpbi4=
LS0tLSstLS0tMS0tLS0rLS0tLTItLS0tKy0tLS0zLS0=
W0NRQy1Jcm9uQnJpZGdlXVtDUUMtSXJvbkJyaWRnZV0=
LS0tLSstLS0tMS0tLS0rLS0tLTItLS0tKy0tLS0zLS0=
Q2FtYnJpZGdlIFF1YW50dW0gQ29tcHV0aW5nIEx0ZC4=
LS0tLSstLS0tMS0tLS0rLS0tLTItLS0tKy0tLS0zLS0=
```
X+HFGXFHKEeblz7t8byycdN+Iu+lEP601nfsaXnc0Yw=

### C6. Testing
Test that all is good
#### openssl engine
Display a list of available engines...
```
$ openssl engine
(rdrand) Intel RDRAND engine
(dynamic) Dynamic engine loading support
(ibrand) RNG engine using the IronBridge API                                 <=== NB
$
```
#### openssl rand 100
Retrieve 100 bytes of random data...
```
$ openssl rand 100
<binary/unprintable data removed>
$
```

### C7. Tips and Tricks


```
export OPENSSL_CONF=/usr/local/ssl/ibrand_openssl.cnf
export IBRAND_CONF=/usr/local/ssl/ibrand.cnf
openssl rand --help
openssl rand --hex 100
openssl rand --base64 100
openssl rand --base64 32
openssl rand -engine rdrand 32
openssl rand -engine ibrand 32
openssl engine
openssl rand -engine dynamic 32
openssl rand -engine dynamix 32
openssl rand -engine dynamic 32
openssl rand -engine ibrand 32
history
```

```
$ openssl rand -engine ibrand -hex 32
Engine "ibrand" set.
5fe1c519714728479b973eedf1bcb271d37e22efa510feb4d677ec6979dcd18c
```

```
$ openssl rand -engine ibrand -base64 32
Engine "ibrand" set.
X+HFGXFHKEeblz7t8byycdN+Iu+lEP601nfsaXnc0Yw=
$
```

Viewing syslog:
```
tail -f /var/log/syslog
tail -f -n 5 /var/log/syslog
```
