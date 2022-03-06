// ----------------------------------------
// HotCalls
// Copyright 2017 The Regents of the University of Michigan
// Ofir Weisse, Valeria Bertacco and Todd Austin

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ---------------------------------------------

//Author: Ofir Weisse, www.OfirWeisse.com, email: oweisse (at) umich (dot) edu
//Based on ISCA 2017 "HotCalls" paper. 
//Link to the paper can be found at http://www.ofirweisse.com/previous_work.html
//If you make nay use of this code for academic purpose, please cite the paper. 


#ifndef __COMMON_H
#define __COMMON_H


#define NET_CLIENT_RECV_PORT 5006
#define NET_PROXY_IP "localhost"
#define NET_PROXY_PORT "5006"
typedef volatile uint32_t sgx_spinlock_t;
typedef unsigned long int pthread_t;

enum OCALL_ID {
    OCALL_PUT,
};

enum ECALL_ID {
    ECALL_PUT,
};

typedef struct {
    uint64_t* cyclesCount;
    uint64_t  counter;
    void*     data; 
    enum OCALL_ID  ocall_id; 
} OcallParams;

typedef struct {
    void*     data; 
    enum ECALL_ID  ecall_id; 
} EcallParams;


typedef struct {
    sgx_spinlock_t  spinlock;
    bool            isRead;
    void*           data;
    int             ocall_id; 
} HotData;


typedef struct {
    sgx_spinlock_t  spinlock;
    pthread_t       responderThread;
    bool            initialized; 
    bool            keepPolling;
    HotData**    MsgQueue;
} HotMsg;



typedef struct{
    uint8_t* sender_name; 
    uint8_t* receiver_name; 

    uint8_t* payload_l;
    uint8_t* payload_in_transit;
    uint8_t* signature;
    
    uint8_t* prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    uint8_t* hash;

    int64_t timestamp;
    uint8_t* msgType;

} capsule_pdu;

typedef struct{
    uint8_t* name; //hash of metadata 
    uint8_t* public_key; 
    uint8_t* identity;
} capsule_advertise;

#endif