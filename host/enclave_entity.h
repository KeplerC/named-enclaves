
#ifndef __ENCLAVE_ENTITY
#define __ENCLAVE_ENTITY

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "attestation_u.h"
#include "hot_msg_pass.h"
#include <thread>
#include <unistd.h>
#include "net.h"

// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};


struct enclave_responder_args {
     oe_enclave_t *client;
     HotMsg *hotMsg;
};


static void* thread_run_ecall_responder(void* hotMsgAsVoidP){
    struct enclave_responder_args *args = (struct enclave_responder_args *) hotMsgAsVoidP;
    int ret = 0;
    EnclaveMsgStartResponder(args->client,  &ret, args->hotMsg);
    return NULL;
}

//handler for ocall -> network
static void *StartOcallResponder( void *arg ) {

    HotMsg *hotMsg = (HotMsg *) arg;

    int dataID = 0;

    static int i;
    __sgx_spin_lock(&hotMsg->spinlock );
    hotMsg->initialized = true;  
    __sgx_spin_unlock(&hotMsg->spinlock);

    while( true )
    {
      if( hotMsg->keepPolling != true ) {
            break;
      }
      
      HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];
      if (data_ptr == 0){
          continue;
      }

      __sgx_spin_lock( &data_ptr->spinlock );

      if(data_ptr->data){
          //Message exists!
          OcallParams *args = (OcallParams *) data_ptr->data; 
          int* result;

          switch(data_ptr->ocall_id){
            case OCALL_PUT:
                result = (int*)args->data; 
                printf("[OCALL] dc data : %d\n", *result);
                break;
            default:
                printf("Invalid ECALL id: %d\n", args->ocall_id);
          }
          data_ptr->data = 0; 
      }

      data_ptr->isRead      = true;
      __sgx_spin_unlock( &data_ptr->spinlock );
      dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
      for( i = 0; i<3; ++i)
          _mm_pause();
  }
}



class Enclave_Entity{
public:
    Enclave_Entity(oe_enclave_t* enclave){
        m_enclave = enclave; 

        //initialize network client 
        m_net = new NetworkClient(this);



        // Initialize the OCALL/ECALL circular buffers for switchless calls 
        circ_buffer_enclave = (HotMsg *) calloc(1, sizeof(HotMsg));   // HOTMSG_INITIALIZER;
        HotMsg_init(circ_buffer_enclave);

        circ_buffer_host = (HotMsg *) calloc(1, sizeof(HotMsg));   // HOTMSG_INITIALIZER;
        HotMsg_init(circ_buffer_host);

        //start ecall responder
        //first argument this->client
        e_responder_args = {m_enclave, circ_buffer_enclave};
        int result = pthread_create(&circ_buffer_enclave->responderThread, NULL, thread_run_ecall_responder, (void*)&e_responder_args );
        if (0 != result)
        {
            fprintf(stderr, ("pthread_create() failed with error #%d: '%s'\n", result, strerror(result)));
            exit(EXIT_FAILURE);
        }

        SetOcallBuffer(m_enclave, &result, circ_buffer_host);
        result = pthread_create(&circ_buffer_host->responderThread, NULL, StartOcallResponder, (void*) circ_buffer_host);
        if (0 != result)
        {
            fprintf(stderr, ("pthread_create() failed with error #%d: '%s'\n", result, strerror(result)));
            exit(EXIT_FAILURE);
        }

    }

    

    void run(){


    }

    void start_ecall(){
        EcallParams *args = (EcallParams *) malloc(sizeof(EcallParams));
        int *data = (int *) malloc(sizeof(int));
        args->ecall_id = ECALL_PUT;
        *data   = 250000;
        args->data = data; 
        for( uint64_t i=0; i < 10; ++i ) {
            printf("[start_ecall] id is: %d\n",requestedCallID);
            HotMsg_requestECall( circ_buffer_enclave, requestedCallID++, args );
        }
    }
private: 
    HotMsg *circ_buffer_enclave;
    HotMsg *circ_buffer_host; 
    uint16_t requestedCallID = 0;
    oe_enclave_t* m_enclave; 
    struct enclave_responder_args e_responder_args;
    NetworkClient* m_net;
};



#endif