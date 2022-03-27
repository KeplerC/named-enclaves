
#ifndef CAPSULE_H
#define CAPSULE_H
#define DELIM ",,,"
#include <string.h>
#include <openenclave/enclave.h>
#include "crypto.h"

class CapsulePDU{
public: 
CapsulePDU(void* buffer, size_t size){

}

CapsulePDU(std::string s, std::string src, std::string dst){
    // payload = new uint8_t[metadata.size()];
    // strcpy((char*) payload, s.c_str());  
    receiver_name = dst; 
    sender_name = src; 

    payload = s; 
}

// void process_crypto(){
//     //encrypt: 
//     m_crypto->Sha256(metadata_in_c_str, metadata.size(), m_name);
//     //metadata += "," + std::string(reinterpret_cast<char*>(m_name));
//     metadata += "," + std::string( m_name, m_name + 32);

//     //hash:
// }

void* to_untrusted_string(){
    payload_in_transit =  std::string("DATA") + DELIM 
        + receiver_name + DELIM 
        + sender_name  + DELIM 
        + payload;

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
    std::string payload; 
    std::string signature;

    std::string prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    std::string hash;

    int64_t timestamp;
    std::string msgType;

    Crypto* m_crypto; 
}; 

class CapsuleAdvertise{
public: 
CapsuleAdvertise(evidence_t* identity, pem_key_t* public_key){
    m_identity = identity;
    m_public_key = public_key;
    m_crypto = new Crypto();
    metadata = std::string("ADV") + DELIM + std::string( identity->buffer,identity->buffer + identity->size)  \
          + DELIM + std::string( public_key->buffer,public_key->buffer + public_key->size) ;
    uint8_t metadata_in_c_str[metadata.size()];
    strcpy((char*) metadata_in_c_str, metadata.c_str());  
    m_crypto->Sha256(metadata_in_c_str, metadata.size(), m_name);
    m_hash = std::string( m_name, m_name + 32);
    metadata += DELIM + m_hash;

}

void* to_untrusted_string(){
    void* ret = oe_host_malloc(metadata.size());
    memcpy(ret, metadata.c_str(), metadata.size());
    //return ret; 
    return ret;
}


size_t get_payload_size(){
    //return name.size();
    return metadata.size();
}

std::string get_my_hash(){
    return m_hash;
}
private: 
    uint8_t m_name[32];//hash of metadata 
    pem_key_t* m_public_key; 
    evidence_t* m_identity;
    std::string metadata; 
    Crypto* m_crypto; 
    std::string m_hash; 
}; 


#endif 
