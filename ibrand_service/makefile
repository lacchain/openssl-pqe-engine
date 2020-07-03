GIT_VERSION := $(shell git --no-pager describe --tags --always)
GIT_COMMIT  := $(shell git rev-parse --verify HEAD)
GIT_DATE    := $(firstword $(shell git --no-pager show --date=iso-strict --format="%ad" --name-only))

COMMON_DIR = ../ibrand_common

CFLAGS = -g -Wall -Wextra -Werror -fPIC -std=c99 -O3 \
 -I Keccak \
 -I /usr/include/libcurl \
 -I $(COMMON_DIR) \
 -DGIT_VERSION=\"$(GIT_VERSION)\"\
 -DGIT_COMMIT=\"$(GIT_COMMIT)\"\
 -DGIT_DATE=\"$(GIT_DATE)\"\
 -DLINUX

.PHONY: all
all: MARKER MY_UTILSLIB IBRAND_SERVICE
	@echo --- $@ Done

MARKER:
	@echo ================================================================================

.PHONY: IBRAND_SERVICE
IBRAND_SERVICE: ibrand_service
	@echo --- $@ Done

ibrand_service: MY_UTILSLIB ibrand_service.o $(COMMON_DIR)/my_utilslib.a
	$(CC) $(CFLAGS) -o ibrand_service ibrand_service.o  $(COMMON_DIR)/my_utilslib.a -lm -lrt -lcurl -L.
	@echo --- $@ Done

ibrand_service.o: ibrand_service.c ibrand_service.h $(COMMON_DIR)/my_utilslib.h
	$(CC) -c -o $@ $< $(CFLAGS)
	@echo --- $@ Done

.PHONY: MY_UTILSLIB
MY_UTILSLIB:
	make -C $(COMMON_DIR) -f Makefile.linux
	@echo --- $@ Done

#%.o: %.c ibrand_service.h
#	$(CC) -c -o $@ $< $(CFLAGS)
#	@echo --- $@ Done

# Prerequisites: 
#     apt-get install libcurl4-openssl-dev

clean:
	-$(RM) ibrand_service *.o *.a *.gch *.so
	@echo --- $@ Done

# We use "install" to do the following...
#	install -d <DEST_PATH>                      # mkdir <DEST_PATH>, including and parents as required.
#	install -m <ATTRS> <FILES> <DEST_PATH>      # copy <FILES> to <DEST_PATH>, and do a chmod <ATTRS> on each.
#	ldconfig <LIB_PATH>                         # Configure Dynamic Linker Run Time Bindings

install: ibrand_service
	@install -d                                           $(PREFIX)/sbin
	install -m 0755 ibrand_service                       $(PREFIX)/sbin/
	@#install -d                                           $(PREFIX)/lib/udev/rules.d/
	#install -m 0644 init_scripts/75-ibrand_service.rules $(PREFIX)/lib/udev/rules.d/
	@#install -d                                           $(PREFIX)/lib/systemd/system
	#install -m 0644 init_scripts/ibrand_service.service  $(PREFIX)/lib/systemd/system
	@echo --- $@ Done

postinstall:
	systemctl restart systemd-udevd
	systemctl enable ibrand_service
	@echo --- $@ Done

show-installed:
	@#ps -aux | grep ibrand_service
	ps -ef | grep ibrand_service
	@#printenv IBRAND_CONF
	@echo --- $@ Done
