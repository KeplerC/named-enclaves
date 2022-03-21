
#ifndef ENCLAVE_RIB
#define ENCLAVE_RIB

#include <iostream>
#include <unordered_map>
#include "common.h"

class RIB {
    std::unordered_map<std::string, std::string> htmap;

public:
    void put(const std::string key, const std::string value) {
        TRACE_ENCLAVE("[ENCLAVE RIB] storing %s to RIB", key.c_str());
        htmap[key] = value;
    }

    const std::string get(const std::string key) {
            return htmap[key];
    }
};

#endif