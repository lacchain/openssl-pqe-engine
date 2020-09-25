
# CQC IronBridge OpenSSL Engine

## Quick Start
To get up and running quickly, please see the following:

* Config files: The "_sample_data" folder contains sample config files.  The Playbook explains that an env var is needed to point to this config file.
* Playbook - This covers the steps required to build, test and deploy the system, as well as some sample commands and sample output.

### Building
The `Dockerfile` image in this distribution is useful for building the library. The container building process compiles the project, e.g.
```shell
$ docker build -f Dockerfile.build . -t pqe_engine
```
and for getting the Debian installer you just run it mounting the `/build/packages/` volume, e.g.
```shell
$ docker run -v `pwd`/output:/build/packages/ --rm pqe_build
```

### Smoke test
Using Docker compose we can follow a minimal installation and usage of the IB engine.
You'll need to create a `ib_password` file containing your password for accessing the Iron Bridge platform in the root of the project, e.g.
```shell
$ echo xxxxxxxx > ib_password
```
and then run
```shell
$ docker-compose up
```
In this composition, a service will build the Debian installer while another one will install and use it


## Component Details

### IBRand OpenSSL Engine

(TODO)

### IBRand Support Library

(TODO)

### IBRand_Service (Daemon)

(TODO)

### Frodo KEM

FrodoKEM: Learning with Errors Key Encapsulation.

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

Modifications: 
 * Makefile modified to be less noisy (no news is good news - tell me if things go wrong, not if things go right)
 * Makefile modified ti highlight option choices - primarily use of OpenSSL for the AES calls.

## Tips, Traps and Gotchas


## Known Issues


