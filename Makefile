# 
# Makefile for kryptonite
#

PKGCONF = pkg-config

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

ifneq ($(shell pkg-config --exists doca-flow && echo 0),0)
$(error "no installation of DOCA found")
endif

# Note: doca-dpdk-bridge is required by doca_dpdk_port_probe
CFLAGS += -g -O3 -Wno-deprecated-declarations -DHAVE_DPDK \
	$(shell $(PKGCONF) --cflags libdpdk) \
	$(shell $(PKGCONF) --cflags doca-flow) \
	$(shell $(PKGCONF) --cflags doca-argp) \
	$(shell $(PKGCONF) --cflags doca-common) \
	$(shell $(PKGCONF) --cflags doca-dpdk-bridge)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)  \
	$(shell $(PKGCONF) --libs doca-flow) \
	$(shell $(PKGCONF) --libs doca-argp) \
	$(shell $(PKGCONF) --libs doca-common) \
	$(shell $(PKGCONF) --libs doca-dpdk-bridge) \
	-lpthread -ldl

APP = kryptonite

SRCS-y := kryptonite.c

$(APP): $(SRCS-y) Makefile
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)

