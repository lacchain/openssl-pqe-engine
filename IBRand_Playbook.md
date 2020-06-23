
# IBRand Playbook
Created: JGilmore (23/06/2020 20:18) 

## Overview
todo

## Credits
Much code derived from the excellent...
* git clone https://github.com/13-37-org/infnoise
* git clone https://github.com/tinskip/infnoise-openssl.git


## Playbook

export PROJECT_DEV_FOLDER=/home/jgilmore/dev/ironbridge.software.ib_openssl

### Install some tools, utilities and libs
sudo apt update
sudo apt upgrade
sudo apt install gcc perl make
sudo apt-get install libftdi-dev
sudo apt install git
sudo apt install net-tools
sudo apt install vim
sudo apt install openssl
sudo apt install openssl-dev
sudo apt-get install libssl-dev

### Get, Build and install OpenSSL (with engine support)
cd $(PROJECT_DEV_FOLDER)
git clone https://github.com/openssl/openssl
cd openssl/
./config
make
sudo make install
cd ..

### Get, Build and install IronBridge IBRand engine
git clone https://gitlab.cqc.local/jgilmore/ironbridge.software.ib_openssl.git  (or similar)
cd ironbridge.software.ib_openssl
# Get, Build and install ibrand engine
cd ibrand_engine/software
sudo make -f Makefile.linux install-lib
cd ../..
cd ibrand_openssl
make
cd ..

### Some manual deployment steps
ls -al ./ibrand_openssl/ibrand_openssl.so
// Expect something like: 
//   -rwxrwxr-x 1 jgilmore jgilmore 13072 Jun 23 18:17 ./ibrand_openssl/ibrand_openssl.so
sudo cp ./ibrand_openssl/ibrand_openssl.so /usr/local/lib/engines-3/
sudo cp ./ibrand_openssl/ibrand_openssl.so /usr/lib/x86_64-linux-gnu/engines-1.1/
ls -al /usr/local/lib/engines-3/
ls -al /usr/lib/x86_64-linux-gnu/engines-1.1/
// Expect both to include: 
//    -rwxr-xr-x 1 root root 24520 Jun 19 00:15 afalg.so
//    -rwxr-xr-x 1 root root  7480 Jun 19 00:15 capi.so
//    -rwxr-xr-x 1 root root 13072 Jun 23 18:19 ibrand_openssl.so
//    -rwxr-xr-x 1 root root 28864 Jun 19 00:15 padlock.so

ls -al ./ibrand_engine/software/libibrand.so
// Expect something like: 
//    -rwxr-xr-x 1 root root 33328 Jun 23 19:01 libibrand.so
ls -al /usr/local/lib/
// Expect it to include: 
//    drwxr-xr-x  2 root root     4096 Jun 23 18:19 engines-3
//    -rw-r--r--  1 root root  8381934 Jun 19 00:15 libcrypto.a
//    lrwxrwxrwx  1 root root       14 Jun 19 00:15 libcrypto.so -> libcrypto.so.3
//    -rwxr-xr-x  1 root root  4672968 Jun 19 00:15 libcrypto.so.3
//    -rw-r--r--  1 root root    33328 Jun 23 19:01 libibrand.so
//    -rw-r--r--  1 root root  1093154 Jun 19 00:15 libssl.a
//    lrwxrwxrwx  1 root root       11 Jun 19 00:15 libssl.so -> libssl.so.3
//    -rwxr-xr-x  1 root root   704576 Jun 19 00:15 libssl.so.3
ls -al /usr/local/include/
// Expect it to include: 
//    -rw-r--r--  1 root root 2897 Jun 23 19:24 libibrand.h
//    drwxr-xr-x  2 root root 4096 Jun 19 00:15 openssl


### Running
Test that all is good
ls -al /home/jgilmore/dev/ironbridge.software.ib_openssl/ibrand_openssl/ibrand_openssl.cnf
// Expect something like: 
//        -rwxr--r-- 1 jgilmore jgilmore 259 Jun 23 17:59 /home/jgilmore/dev/ironbridge.software.ib_openssl/ibrand_openssl/ibrand_openssl.cnf

export OPENSSL_CONF="$(PROJECT_DEV_FOLDER)/ibrand_openssl/ibrand_openssl.cnf"
// e.g. export OPENSSL_CONF="/home/jgilmore/dev/ironbridge.software.ib_openssl/ibrand_openssl/ibrand_openssl.cnf"
export IBRAND_CONF="$(PROJECT_DEV_FOLDER)/ibrand.cnf"
// e.g. export IBRAND_CONF="/home/jgilmore/dev/ironbridge.software.ib_openssl/ibrand.cnf"

sudo mkdir /var/lib/ibrand
sudo cp ./ibrand_data.bin /var/lib/ibrand/
ls -al /var/lib/ibrand/
// Expect something like: 
//    -rwxr--r--  1 jgilmore jgilmore 3600 Jun 23 19:38 ibrand_data.bin

openssl engine
openssl engine ibrand_openssl
sudo openssl engine ibrand_openssl

### Expected Output

#### openssl engine
```
$ openssl engine
initIBRand: IB_SOURCE_OF_RANDOMNESS == RANDSRC_FILE
IBRand engine loaded.
(rdrand) Intel RDRAND engine
(dynamic) Dynamic engine loading support
(ibrand) RNG engine using the IronBridge API
$
```

#### openssl rand 100
```
$ openssl rand 100
initIBRand: IB_SOURCE_OF_RANDOMNESS == RANDSRC_FILE
IBRand engine loaded.
INFO: processBytes returned 32
INFO: processBytes returned 32
INFO: processBytes returned 32
INFO: processBytes returned 32
<binary/unprintable data removed>
$
```
