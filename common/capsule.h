
#ifndef CAPSULE_H
#define CAPSULE_H

#include <string.h>
#include <openenclave/enclave.h>

class CapsulePDU{
public: 
CapsulePDU(void* buffer, size_t size){

}

CapsulePDU(std::string s){
    payload_in_transit = s;
}

void* to_untrusted_string(){
    void* ret = oe_host_malloc(payload_in_transit.size());
    memcpy(ret, payload_in_transit.c_str(), payload_in_transit.size());
    return ret; 
}

size_t get_payload_size(){
    return payload_in_transit.size();
}

private: 
    std::string sender_name; 
    std::string receiver_name; 

    std::string payload_in_transit;
    std::string signature;

    std::string prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    std::string hash;

    int64_t timestamp;
    std::string msgType;
}; 

class CapsuleAdvertise{
public: 
CapsuleAdvertise(void* buffer, size_t size){

}

void* to_untrusted_string(){
    //void* ret = oe_host_malloc(name.size());
    //memcpy(ret, name.c_str(), name.size());
    //return ret; 
    return 0;
}

size_t get_payload_size(){
    //return name.size();
    return 0;
}

private: 
    uint8_t* name; //hash of metadata 
    uint8_t* public_key; 
    uint8_t* identity;
}; 


#endif 
