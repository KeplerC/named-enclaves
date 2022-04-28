
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
#include "log.h"
#include "oe_helpers.h"


// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static uint32_t enclave_flags = OE_ENCLAVE_FLAG_DEBUG;

struct enclave_responder_args {
     oe_enclave_t *client;
     HotMsg *hotMsg;
};


struct ocall_responder_args {
     NetworkClient* net_addr;
     HotMsg *hotMsg;
};


static void* thread_run_ecall_responder(void* hotMsgAsVoidP){
    struct enclave_responder_args *args = (struct enclave_responder_args *) hotMsgAsVoidP;
    int ret = 0;
    EnclaveMsgStartResponder(args->client,  &ret, args->hotMsg);
    return NULL;
}

static void* thread_run_net_client(void* net_client){
    ((NetworkClient*) net_client)->run_message_receiver();
    return NULL;
}

//handler for ocall -> network
static void *StartOcallResponder( void *hot_msg_as_void_ptr ) {

    zmq::context_t context (1);
    // to router
    zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_ptr -> connect ("tcp://" + std::string(NET_PROXY_IP) + ":" + std::string(NET_PROXY_PORT));

    struct ocall_responder_args *args = (struct ocall_responder_args *) hot_msg_as_void_ptr;
    HotMsg *hotMsg = (HotMsg *) args->hotMsg;
    NetworkClient *nc = (NetworkClient *) args->net_addr;
    std::string m_address = nc->get_addr();
    TRACE_ENCLAVE("Using Address: %s", m_address.c_str());

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
          zmq::message_t* msg;
          std::string payload; 

          switch(data_ptr->ocall_id){
            case OCALL_PUT:
                // printf("[OCALL-circular-buffer] arg data arg ptr : %d\n", args);
                // printf("[OCALL-circular-buffer] arg data size : %d\n", args->data_size);
                // printf("[OCALL-circular-buffer] arg data size : %s\n", args->data);
                // msg = new zmq::message_t(args->data_size);
                // memcpy(msg->data(), args->data, args->data_size);
                // socket_ptr->send(*msg);

                payload = std::string((char*) args->data, args->data_size) + ",,," + m_address;
                msg = new zmq::message_t(payload.size());
                memcpy(msg->data(), payload.c_str(), payload.size());
                socket_ptr->send(*msg);

                // printf("[OCALL-circular-buffer] dc data : %s\n", msg->data());
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
    Enclave_Entity(const char* enclave_name, const char* enclave_path){
        printf("\n=============================");
        printf("Initiating enclave %s", enclave_name);
        printf("=============================\n");
        m_enclave = create_enclave(enclave_path, enclave_flags);; 
        if (m_enclave == NULL)
        {
            printf("Enclave creation failed!\n");
            exit(EXIT_FAILURE);
        }
        
        //initialize network client thread
        m_net = new NetworkClient(this);

        // m_addr = "localhost:" + std::to_string(m_net -> get_port());
        // TRACE_ENCLAVE("Using Address: %s", m_addr.c_str());
        int result = pthread_create(&m_net_client_thread, NULL, thread_run_net_client, (void*)m_net);
        if (0 != result)
        {
            fprintf(stderr, ("pthread_create() failed with error #%d: '%s'\n", result, strerror(result)));
            exit(EXIT_FAILURE);
        }

        // Initialize the OCALL/ECALL circular buffers for switchless calls 
        circ_buffer_enclave = (HotMsg *) calloc(1, sizeof(HotMsg));   // HOTMSG_INITIALIZER;
        HotMsg_init(circ_buffer_enclave);

        circ_buffer_host = (HotMsg *) calloc(1, sizeof(HotMsg));   // HOTMSG_INITIALIZER;
        HotMsg_init(circ_buffer_host);

        //start ecall responder
        //first argument this->client
        e_responder_args = {m_enclave, circ_buffer_enclave};
        result = pthread_create(&circ_buffer_enclave->responderThread, NULL, thread_run_ecall_responder, (void*)&e_responder_args );
        if (0 != result)
        {
            fprintf(stderr, ("pthread_create() failed with error #%d: '%s'\n", result, strerror(result)));
            exit(EXIT_FAILURE);
        }

        SetOcallBuffer(m_enclave, &result, circ_buffer_host);

        o_responder_args = {m_net, circ_buffer_host};
        result = pthread_create(&circ_buffer_host->responderThread, NULL, StartOcallResponder, (void*) &o_responder_args);
        if (0 != result)
        {
            fprintf(stderr, ("pthread_create() failed with error #%d: '%s'\n", result, strerror(result)));
            exit(EXIT_FAILURE);
        }

        printf("Enclave %s creation successful!\n", enclave_name);

    }

    void advertise(){
        printf("\n=============================");
        printf("Generating Identity");
        printf("=============================\n");
        generate_identity_report(format_id, "enclave_a", m_enclave, evidence, pem_key); 

    }
    

    void run(){
        printf("\n=============================");
        printf("Running In-Enclave User's Code");
        printf("=============================\n");
        EnclaveSampleCode(m_enclave);
    }

    void ecall_send_to_enclave(void* data, size_t data_size){
        EcallParams *args = (EcallParams *) malloc(sizeof(EcallParams));
        args->ecall_id = ECALL_PUT;
        args->data = data;
        args->data_size = data_size; 
        // printf("[start_ecall] id is: %d\n",requestedCallID);
        HotMsg_requestECall( circ_buffer_enclave, requestedCallID++, args);
    }

    std::string m_addr; 
private: 
    oe_enclave_t* m_enclave; 
    // circular buffer
    HotMsg *circ_buffer_enclave;
    HotMsg *circ_buffer_host; 
    uint16_t requestedCallID = 0;
    // networking 
    struct enclave_responder_args e_responder_args;
    struct ocall_responder_args o_responder_args;
    NetworkClient* m_net;
    pthread_t m_net_client_thread;
    //identity related 
    oe_uuid_t* format_id = &sgx_remote_uuid;
    evidence_t evidence = {0};
    pem_key_t pem_key = {0};

    

private: 
    oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
    {
        oe_enclave_t* enclave = NULL;

        printf("Host: Enclave library %s\n", enclave_path);
        oe_result_t result = oe_create_attestation_enclave(
            enclave_path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

        if (result != OE_OK)
        {
            printf(
                "Host: oe_create_attestation_enclave failed. %s",
                oe_result_str(result));
        }
        else
        {
            printf("Host: Enclave successfully created.\n");
        }
        return enclave;
    }

    void terminate_enclave(oe_enclave_t* enclave)
    {
        oe_terminate_enclave(enclave);
        printf("Host: Enclave successfully terminated.\n");
    }


    int generate_identity_report(    
            const oe_uuid_t* format_id,
            const char* attester_enclave_name,
            oe_enclave_t* attester_enclave,
            evidence_t& evidence,
            pem_key_t& pem_key
        ){
        oe_result_t result = OE_OK;
        int ret = 1;
        format_settings_t format_settings = {0};
        
        printf("Use its own format setting\n");
        result = get_enclave_format_settings(attester_enclave, &ret, format_id, &format_settings);

        if ((result != OE_OK) || (ret != 0))
        {
            printf("Host: get_format_settings failed. %s\n", oe_result_str(result));
            if (ret == 0)
                ret = 1;
            goto exit;
        }

        printf(
            "Host: Requesting %s to generate a targeted evidence with an "
            "encryption key\n",
            attester_enclave_name);

        result = get_evidence_with_public_key(
            attester_enclave,
            &ret,
            format_id,
            &format_settings,
            &pem_key,
            &evidence);
        if ((result != OE_OK) || (ret != 0))
        {
            printf(
                "Host: get_evidence_with_public_key failed. %s\n",
                oe_result_str(result));
            if (ret == 0)
                ret = 1;
            goto exit;
        }

    exit:
        free(format_settings.buffer);
        return ret;
    }

    int verify_identity_report(
        const oe_uuid_t* format_id,
        const char* verifier_enclave_name,
        oe_enclave_t* verifier_enclave,
        evidence_t evidence, 
        pem_key_t pem_key
    ){
        oe_result_t result = OE_OK;
        int ret = 1;
        format_settings_t format_settings = {0};
        get_enclave_format_settings(verifier_enclave, &ret, format_id, &format_settings);


        printf(
            "Host: verify_evidence_and_set_public_key in %s\n",
            verifier_enclave_name);
        result = verify_evidence_and_set_public_key(
            verifier_enclave, &ret, format_id, &pem_key, &evidence, &pem_key);
        if ((result != OE_OK) || (ret != 0))
        {
            printf(
                "Host: verify_evidence_and_set_public_key failed. %s\n",
                oe_result_str(result));
            if (ret == 0)
                ret = 1;
            goto exit;
        }

    exit:
        free(format_settings.buffer);
        return ret;
    }

};



#endif