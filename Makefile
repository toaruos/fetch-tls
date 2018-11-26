CC=i686-pc-toaru-gcc
CFLAGS=-I/home/klange/Projects/third-party/mbedtls-2.5.1/include -L/home/klange/Projects/third-party/mbedtls-2.5.1/library
LDFLAGS=-lmbedtls -lmbedx509 -lmbedcrypto

all: fetch

