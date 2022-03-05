# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run: runsgxlocal runsgxremote

runsgxlocal:
	host/attestation_host sgxlocal ./enclave/enclave.signed ./enclave/enclave.signed

runsgxremote:
	host/attestation_host sgxremote ./enclave/enclave.signed ./enclave/enclave.signed
