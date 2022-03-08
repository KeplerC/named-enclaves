
#ifndef CAPSULE_H
#define CAPSULE_H

#include <string.h>
#include <openenclave/enclave.h>
#include "crypto.h"

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
CapsuleAdvertise(evidence_t identity, pem_key_t public_key){
    m_identity = identity;
    m_public_key = public_key;
    m_crypto = new Crypto();
    m_crypto->Sha256(public_key.buffer, sizeof(public_key.buffer), m_name);
}

void* to_untrusted_string(){
    // void* ret = oe_host_malloc(name.size());
    // memcpy(ret, name.c_str(), name.size());
    // //return ret; 
    return m_name;
}

size_t get_payload_size(){
    //return name.size();
    return 0;
}

private: 
    uint8_t m_name[32];//hash of metadata 
    pem_key_t m_public_key; 
    evidence_t m_identity;
    Crypto* m_crypto; 
}; 


#endif 
