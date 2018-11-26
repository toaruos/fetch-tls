CC=i686-pc-toaru-gcc
CFLAGS=-I$(TOARU_SYSROOT)/../userspace/
LDFLAGS=-ltoaru-http_parser -lmbedtls -lmbedx509 -lmbedcrypto -lm

all: fetch

