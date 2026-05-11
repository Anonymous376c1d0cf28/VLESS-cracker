CC ?= cc
PCAP_CONFIG := $(shell command -v pcap-config 2>/dev/null)
PKG_CONFIG := $(shell command -v pkg-config 2>/dev/null)
PCAP_CFLAGS := $(shell if [ -n "$(PCAP_CONFIG)" ]; then $(PCAP_CONFIG) --cflags; elif [ -n "$(PKG_CONFIG)" ] && $(PKG_CONFIG) --exists libpcap; then $(PKG_CONFIG) --cflags libpcap; fi)
PCAP_LIBS := $(shell if [ -n "$(PCAP_CONFIG)" ]; then $(PCAP_CONFIG) --libs; elif [ -n "$(PKG_CONFIG)" ] && $(PKG_CONFIG) --exists libpcap; then $(PKG_CONFIG) --libs libpcap; else printf '%s' '-lpcap'; fi)
THREAD_FLAGS ?= -pthread
CFLAGS ?= -Wall -Wextra -O2
LDLIBS ?= $(PCAP_LIBS)

.PHONY: all clean

all: vless-cracker-v1

vless-cracker-v1: vless-cracker-v1.c
	$(CC) $(CFLAGS) $(THREAD_FLAGS) $(PCAP_CFLAGS) -o $@ $< $(LDLIBS) $(THREAD_FLAGS)

clean:
	rm -f vless-cracker-v1
