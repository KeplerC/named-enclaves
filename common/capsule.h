
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
CapsuleAdvertise(evidence_t* identity, pem_key_t* public_key){
    m_identity = identity;
    m_public_key = public_key;
    m_crypto = new Crypto();
    //m_crypto->Sha256(m_public_key->buffer, sizeof(m_public_key->buffer), m_name);
    m_name = m_public_key->buffer; 
}

void* to_untrusted_string(){
    void* ret = oe_host_malloc(2048);
    memcpy(ret, m_name, 2048);
    //return ret; 
    return ret;
}

// void* to_untrusted_string(){
//     std::string payload_in_transit = "hello jkldsfjkl;asdjfk;lsajklfd;;slkafsafjkdls-----BEGIN PUBLIC KEY-----\
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxm3aImvOOyCQYVDKfK7P\
// pdZ5gjvXJHwDVrttwdknLCumaCOxFRge1lwZ3SICUEUhAJDPJjy1vcWLulhhjxHh\
// EEWg7prpvKnXdr/SAGjJORv+iSUeUxIE2CjUoQVhXlsG2g3XOzLw/JLKlEz1ro+x\
// jUmd/C45+d/sEiqdvZYATAiWW0rVecKJAaMZPkBbbNAz8dyZQy76rRYE27Llc0Xh\
// OXOO1P4SEe/L8WkmV4PzuYBg4pioKsrddYkbEKcmEUzngxiepqsfXyJoYHhCJyTP\
// l3v67y37tQDj2zF7kRxQ3z59ax1tuBx+dL7nHu0MSoQNFbIeDizwImp+94SIgkpZ\
// KwIDAQAB";
//     void* ret = oe_host_malloc(payload_in_transit.size());
//     memcpy(ret, payload_in_transit.c_str(), payload_in_transit.size());
//     return ret; 
// }

size_t get_payload_size(){
    //return name.size();
    return 2048;
}

private: 
    uint8_t* m_name;//hash of metadata 
    pem_key_t* m_public_key; 
    evidence_t* m_identity;
    Crypto* m_crypto; 
}; 


#endif 
