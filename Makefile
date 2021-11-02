CC=x86_64-pc-toaru-gcc
CFLAGS=-I/home/klange/Projects/third-party/mbedtls-2.26.0/include -L/home/klange/Projects/third-party/mbedtls-2.26.0/library
LDFLAGS=-lmbedtls -lmbedx509 -lmbedcrypto

all: fetch

fetch-tls.tgz: fetch
	mkdir -p pkg/usr/bin
	cp fetch pkg/usr/bin/
	cd pkg && tar -czvf ../$@ .
