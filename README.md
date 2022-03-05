
To build

```
mkdir build  && cd build 
cmake ..
make
make run
```

to develop
```
cd ../ && rm -rf build && mkdir build && cd build && cmake .. && make runsgxremote
```


/opt/openenclave/bin/oegdb -arg host/attestation_host  enclave/enclave_a.signed