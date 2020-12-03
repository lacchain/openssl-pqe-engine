
# CQC IronBridge OpenSSL Engine

## Quick Start
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


## Tips, Traps and Gotchas


## Known Issues


