
# CQC IronBridge OpenSSL Engine

# Description

This repo contains the implementation of an OpenSSL engine for Linux to replace the default RNG functionality with that with randomness from CQC IronBridge.

The system was developed on Ubunto 20.04 LTS, and has also been tested on Ubunto 18.04 LTS and within a Docker container on Debian.

It is implemented as a series of static and dynamic libraries shared objects and requires network connectivity to an IronBridge server exposing the IronBridge API.


## Quick Start with Docker
To get up and running quickly, please see the following:

* Config files: The "_sample_data" folder contains sample config files.  The Playbook explains that an env var is needed to point to this config file.
* Playbook - This covers the steps required to build, test and deploy the system, as well as some sample commands and sample output.


### Building
The `Dockerfile` image in this distribution is a multi-stage build used for building a debian package and then installing it to start retrieving remote entropy.
To just extract the Debian package you should run
```shell
$ docker build --target builder . -t pqe_build
$ docker run pqe_build cat /openssl-pqe-engine_0.1.0_amd64.deb > openssl-pqe-engine_0.1.0_amd64.deb
```

### Smoke test
As said, the multi-stage build is ready for running a smoke test against a [PQE RPC server](https://github.com/lacchain/pqe-rpc-server-ng/) instance. You must mount the following volumes 
  * **/certs/client.pem**: client certificate
  * **/certs/client_key.pem**: client certificate private key
E.g.:
```shell
$ docker build . -t pqe_run
$ docker run -v `pwd`/client.crt:/certs/client.pem -v `pwd`/client.key:/certs/client_key.pem --rm pqe_run
```


## Overview

This engine is implemented as several components

* The IBRand Engine - This gets bound into OpenSSL at runtime.
* The main IBRand shared/dynamic library - On request from the engine, this library retrieves any required randomness from a local cache/storage-tank (see below).
* A local cache ("storage tank") of IronBridge entropy implemented as a block of shared memory.
* The IBRand daemon/service - The primary job is to *securely* acquire randomness from the IronBridge Server in order to keep the storage-tank topped-up.
* A static library containing various generic utility functions
* Two confiuration files:
  * A) openssl_conf.cnf  used by openssl to configure engines etc
  * B) ibrand.cnf openssl - used by the various engine components to configure authentication, security, performance, logging etc.
* Two environment variables
  * A) OPENSSL_CONF - points to location of openssl_conf.cnf
  * B) IBRAND_CONF - points to location of ibrand.cnf

## Component Details

### IBRand OpenSSL Engine

(TODO)

### IBRand Support Library

(TODO)

### IBRand_Service (Daemon)

(TODO)

### LibOQS

This project uses post-quantum/quantum-resistant crypto algorithms from the open source LibOQS implementation.

Specifically, we use the shared library as built by the [liboqs-debian](https://github.com/lacchain/liboqs-debian/) project.

### Frodo KEM (LWEKE)

FrodoKEM: Learning with Errors Key Encapsulation (LWEKE)

FrodoKEM is a family of key-encapsulation mechanisms that are designed to be
conservative yet practical post-quantum constructions whose security derives
from cautious parameterizations of the well-studied learning with errors
problem.

We are using the PQCrypto-LWEKE reference implementation:
    https://github.com/microsoft/PQCrypto-LWEKE
Sources retrieved from...
    https://github.com/microsoft/PQCrypto-LWEKE/archive/master.zip
Resulting in...
    PQCrypto-LWEKE-master.zip	30,995,776	15/07/2020 17:42	-a--

We could also use...
    git clone https://github.com/microsoft/PQCrypto-LWEKE.git

=====================================================================================================

## Deployment Guide

Install steps for IronBridge openSSL engine
N.B. Deployed on Ubuntu 20.04.1 LTS

### Dependencies

* https://github.com/open-quantum-safe/openssl (v1.1.1i downloaded)
* https://github.com/open-quantum-safe/liboqs
* https://gitlab.cqc.local/jgilmore/ironbridge.software.ib_openssl CQC IBrand engine

### Required Packages

```shell
sudo apt install cmake gcc ninja-build libssl-dev pysthon3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz libtool git libcurl4-openssl-dev
```

### Update System OpenSSL

Update OpenSSL to latest version manually using tar from https://www.openssl.org/source/openssl-1.1.1i.tar.gz
(think? because you need system support for elliptic curve, debug, dev etc)

```shell
./config
make
sudo make install
sudo ldconfig (cause they don’t link their own libs…!)
```

### Get and Build LibOQS
Then install the liboqs and openSSL.

```shell
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=openssl1.1.1i_from_liboqs/oqs ..
ninja
ninja install

### Get and Build OQS version of OpenSSL

```shell
 cd openssl1.1.1i_from_liboqs
./Configure no-shared linux-x86_64 -lm
make -j
```

This seems to crash/die at the make of the tests, just make the binary to avoid

```shell
make ./apps/openSSL
```

Verify the version you have installed

```shell
./apps/openssl version
```

It should return something similar to:

```
OpenSSL 1.1.1i  8 Dec 2020, Open Quantum Safe xxxx-xx snapshot
```

Test that the engine interface is functioning correctly:

```shell
openssl engine
```

Since we haven't yet configured our engines, the output should be similar to:
```
(rdrand) Intel RDRAND engine
(dynamic) Dynamic engine loading support
```

### Get and Build IBRand Engine

To build the engine, run the following:

```shell
./go.sh build
```

The PQCRYPTO_INCDIR_LOCAL assumes the directory for liboqs is $HOME/liboqs/build/include

#### Configure OpenSSL to load our IBRand and IBInit engines

Set up the environment variables to point to the correct places. This can be in ether the system or user space. In this deployment we put the config files into system directories and copy in the sample file, as shown in Appendix A.

```shell
sudo cp _sample_data/ibrand_openssl.cnf /usr/local/ssl/ibrand_openssl.cnf
export OPENSSL_CONF=/usr/local/ssl/ibrand_openssl.cnf
```

#### Configure IBRand engine

We need the IronBridge config file in place to load the engine properly:

```shell
sudo cp _sample_data/ibrand.cnf /usr/local/ssl/ibrand.cnf
export IBRAND_CONF=/usr/local/ssl/ibrand.cnf
```

#### Start the service

Starting the service will show that we need to set up KEMs and Certificates, start with:

```shell
./ibrand_service/ibrand_service
```

Look in /var/log/syslog for current status, it should be something like:

```
===ibrand_service==================================================================================================
HOST ibrand_service[20364]: INFO: IBRand Service started successfully (pid:20365)
HOST ibrand_service[20365]: INFO: CQC IronBridge IBRand Service Started Successfully (pid:20365)====================
HOST ibrand_service[20365]: INFO: Running
HOST ibrand_service[20365]: INFO: Stats(AUTH(S0,F0,f0),RNG(S0,F0,f0),STORE(Filling ,L0))
HOST ibrand_service[20365]: INFO: Initialising client from OOB data.
HOST ibrand_service[20365]: ERROR: File not found: "~/oob/ironbridge_clientsetup_OOB_1.json"
HOST ibrand_service[20365]: ERROR: Failed to read contents of OOB file "~/oob/ironbridge_clientsetup_OOB_1.json"
HOST ibrand_service[20365]: ERROR: Failed to read contents of OOB segment 1 - "~/oob/ironbridge_clientsetup_OOB_1.json"
HOST ibrand_service[20365]: ERROR: Failed to get binary data from OOB file "/usr/local/ssl/ibrand_sk.bin"
HOST ibrand_service[20365]: ERROR: Failed to import KEM secret key from OOB file
HOST ibrand_service[20365]: FATAL: Configuration error. Aborting. rc=19620
```

#### Client Authentication

Now we need a client certificate (for auth) and an out-of-band KEM key to initialise.

N.B. Verify your connectivity to the server (dev.ironbridgeapi.com) a hosts file change may be necessary. As of writing the IP of the dev server is 51.11.191.53.

The ibrand.cnf file configures where to look for these files (see appendix).

Place the certificate and private key in the configured locations, e.g.:

```shell
sudo cp ~/client_cert.pem $HOME/oob/
sudo cp ~/client_key.pem $HOME/oob/
```

#### KEM Keys

Now we can load the OOB KEM key.

```shell
cp _sample_data/OOB.json $HOME/oob/oob_kem.json
```

And update the config file appropriately. You need to verify the ibrand_sk.bin file is writeable in the location, a (dirty) fix for the default is to put it in:

```
/tmp/ibrand_sk.bin
```

If the KEM key is invalid (likely on first run) then you should now have an output similar to:

```
PROGRESS: STATE_DECAPSULATESHAREDSECRET
HOST ibrand_service[23796]: INFO: Decapsulating SharedSecret
HOST ibrand_service[23796]: ERROR: KEM secret key error (size=0)
HOST ibrand_service[23796]: ERROR: KEM decapsulation failed with rc=19830. Will retry in 5 seconds
```

#### All good - Retrieving Randomness

Once the KEM key is valid then you will receive entropy and will eventually see:

```
INFO: HighWaterMark reached. Pausing retrieval.
```

#### Manual Tests

Tests you can do:

```shell
~/liboqs_openssl/apps/openssl rand 10 -hex
~/liboqs_openssl/apps/openssl genrsa 2048
~/liboqs_openssl/apps/openssl genpkey -algorithm dilithium2
~/liboqs_openssl/apps/openssl speed frodo640shake
```

## Modifications:
 * Makefile modified to be less noisy (no news is good news - tell me if things go wrong, not if things go right)
 * Makefile modified to highlight option choices - primarily use of OpenSSL for the AES calls.

## Tips, Traps and Gotchas

(Watch this space)

## Known Issues

(Hopefully, you won't really need to watch this space)


## Appendix A - ibrand_openssl.cnf

ibrand_openssl.cnf

```shell
# This openssl configuration file enables the IronBridge ibrand and ibinit RNG engines.

openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
ibrand = ibrand_section
ibinit = ibinit_engine_section

[ibrand_section]
engine_id = ibrand_engine
default_algorithms = RAND
init = 0

[ibinit_engine_section]
engine_id = ibinit_engine
init = 0

ibrand.cnf
JSON:{
  "GeneralSettings":
  {
    "_1_Verbosity_bitmapped_field":"STATUS=1, CONFIG=2, PROGRESS=4, AUTH=8, DATA=16, CURL=32, SPARE6=64, SPARE7=128",
    "LOGGING_VERBOSITY":"31"
  },
  "AuthSettings":
  {
    "AUTHTYPE":"CLIENT_CERT",
    "AUTHURL":"https://dev.ironbridgeapi.com/api/login",
    "AUTHUSER":"notused1",
    "AUTHPSWD":"notused2",
    "AUTHSSLCERTTYPE":"PEM",
    "AUTHSSLCERTFILE":"/home/ben/oob/client_cert.pem",
    "AUTHSSLKEYFILE":"/home/ben/oob/client_key.pem",
    "AUTHRETRYDELAY":"5"
  },
  "SecuritySettings":
  {
    "USESECURERNG":"1",
    "PREFERRED_KEM_ALGORITHM":"222",
    "CLIENTSETUP_OOB_PATH":"/home/ben/oob/",
    "CLIENTSETUP_OOB1_FILENAME":"oob_kem.json",
    "CLIENTSETUP_OOBN_FILENAME":"ironbridge_clientsetup_OOB_%d.json",
    "OURKEMSECRETKEYFILENAME":"/tmp/ibrand_sk.bin"
  },
  "CommsSettings":
  {
    "BASEURL":"https://dev.ironbridgeapi.com/api",
    "BYTESPERREQUEST":"4096",
    "RETRIEVALRETRYDELAY":"3"
  },
  "StorageSettings":
  {
    "STORAGETYPE":"SHMEM",
    "FILE_DATAFORMAT":"RAW",
    "FILE_FILENAME":"/var/lib/ibrand/ibrand_data.bin",
    "FILE_LOCKFILEPATH":"/tmp",
    "FILE_HIGHWATERMARK":"30000",
    "FILE_LOWWATERMARK":"20000",
    "SHMEM_BACKINGFILENAME":"shmem_ibrand01",
    "SHMEM_SEMAPHORENAME":"sem_ibrand01",
    "SHMEM_STORAGESIZE":"102400",
    "SHMEM_LOWWATERMARK":"40960",
    "IDLEDELAY":"1"
  }
}
```

