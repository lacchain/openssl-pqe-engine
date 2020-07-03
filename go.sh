#!/bin/bash
#set -x

if [[ $1 = "build" ]]
then
	echo --- Build Support Library
	pushd ibrand_lib/software/
	sudo make -f Makefile.linux install-lib
	popd
	echo --- Build RNG Engine for OpenSSL 
	pushd ibrand_openssl/
	sudo make -f Makefile.linux install-lib
	popd
	echo --- Build Service
	pushd ibrand_service/
	sudo make
	popd
	echo --- Done
elif [[ $1 = "rebuild" ]]
then
	echo --- ReBuild Support Library
	pushd ibrand_lib/software/
	sudo make -f Makefile.linux install-lib -B
	popd
	echo --- ReBuild RNG Engine for OpenSSL 
	pushd ibrand_openssl/
	sudo make -f Makefile.linux install-lib -B
	popd
	echo --- ReBuild Service
	pushd ibrand_service/
	sudo make -B
	popd
	echo --- Done
elif [[ $1 = "runsvc" ]]
then
	#sudo ibrand_service/ibrand_service
	sudo ibrand_service/ibrand_service -f /usr/local/ssl/ibrand.cnf
	pgrep ibrand_service -l
	tail -f -n 10 /var/log/syslog
elif [[ $1 = "viewsvc" ]]
then
	pgrep ibrand_service -l
elif [[ $1 = "viewlog" ]]
then
	tail -f -n 10 /var/log/syslog
elif [[ $1 = "showall" ]]
then
	echo --- Files:
	sudo find /var       -printf "%c %p\n" | grep -i ibrand
	sudo find /usr/local -printf "%c %p\n" | grep -i ibrand
	sudo find /tmp       -printf "%c %p\n" | grep -i ibrand
	echo --- Environment Variable OPENSSL_CONF:
	printenv OPENSSL_CONF 
	echo --- Environment Variable IBRAND_CONF:
	printenv IBRAND_CONF
	echo --- OpenSSL engines
	openssl engine
	echo --- Services:
	#ps -ef | grep ibrand_service
	pgrep ibrand_service -l
	echo '--- Syslog [tail 10 only]:'
	tail -n 10 /var/log/syslog
	echo --- Done
else
	echo "Usage: $0 build|rebuild|runsvc|viewsvc|viewlog|showall"
fi

