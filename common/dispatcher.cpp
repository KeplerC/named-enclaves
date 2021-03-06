// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <iostream>
#include <vector>
#include <iomanip> 
#include <sstream>
#include "dispatcher.h"
#include "common.h"
#include "capsule.h"
#include "net_roles.h"
#include "duktape/duktape.h"


ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(nullptr), m_attestation(nullptr)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == nullptr)
    {
        goto exit;
    }

    m_attestation = new Attestation(m_crypto);
    if (m_attestation == nullptr)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

int ecall_dispatcher::get_enclave_format_settings(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings)
{
    uint8_t* format_settings_buffer = nullptr;
    size_t format_settings_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    TRACE_ENCLAVE("get_enclave_format_settings");
    if (m_attestation->get_format_settings(
            format_id, &format_settings_buffer, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("get_enclave_format_settings failed");
        goto exit;
    }

    if (format_settings_buffer && format_settings_size)
    {
        format_settings->buffer = (uint8_t*)malloc(format_settings_size);
        if (format_settings->buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("copying format_settings failed, out of memory");
            goto exit;
        }
        memcpy(
            format_settings->buffer,
            format_settings_buffer,
            format_settings_size);
        format_settings->size = format_settings_size;
        oe_verifier_free_format_settings(format_settings_buffer);
    }
    else
    {
        format_settings->buffer = nullptr;
        format_settings->size = 0;
    }
    ret = 0;

exit:

    if (ret != 0)
        TRACE_ENCLAVE("get_enclave_format_settings failed.");
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. The enclave that receives the key will use the evidence to
 * attest this enclave.
 */
int ecall_dispatcher::get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    uint8_t pem_public_key[512];
    uint8_t* evidence_buffer = nullptr;
    size_t evidence_size = 0;
    int ret = 1;

    TRACE_ENCLAVE("get_evidence_with_public_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_attestation_evidence(
            format_id,
            format_settings->buffer,
            format_settings->size,
            pem_public_key,
            sizeof(pem_public_key),
            &evidence_buffer,
            &evidence_size) == false)
    {
        TRACE_ENCLAVE("get_evidence_with_public_key failed");
        goto exit;
    }

    evidence->buffer = (uint8_t*)malloc(evidence_size);
    if (evidence->buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying evidence_buffer failed, out of memory");
        goto exit;
    }
    memcpy(evidence->buffer, evidence_buffer, evidence_size);
    evidence->size = evidence_size;
    oe_free_evidence(evidence_buffer);

    pem_key->buffer = (uint8_t*)malloc(sizeof(pem_public_key));
    if (pem_key->buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying key_buffer failed, out of memory");
        goto exit;
    }
    memcpy(pem_key->buffer, pem_public_key, sizeof(pem_public_key));
    pem_key->size = sizeof(pem_public_key);

    ret = 0;
    TRACE_ENCLAVE("get_evidence_with_public_key succeeded");

    put_advertisement(pem_key, evidence);

exit:
    if (ret != 0)
    {
        if (evidence_buffer)
            oe_free_evidence(evidence_buffer);
        if (pem_key)
        {
            free(pem_key->buffer);
            pem_key->size = 0;
        }
        if (evidence)
        {
            free(evidence->buffer);
            evidence->size = 0;
        }
    }
    return ret;
}

int ecall_dispatcher::verify_evidence_with_public_key(
    const oe_uuid_t* format_id,
    pem_key_t* pem_key,
    evidence_t* evidence,
    const char* other_enclave_signing_key_pem, 
    size_t other_enclave_signing_key_pem_size
    )
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(
            format_id,
            evidence->buffer,
            evidence->size,
            pem_key->buffer,
            pem_key->size, 
            other_enclave_signing_key_pem, 
           other_enclave_signing_key_pem_size) == false)
    {
        TRACE_ENCLAVE("verify_evidence_and_set_public_key failed.");
        goto exit;
    }

    // memcpy(
    //     m_crypto->get_the_other_enclave_public_key(),
    //     pem_key->buffer,
    //     pem_key->size);

    ret = 0;

exit:
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(
    message_t* message, 
    pem_key_t* other_enclave_pem_key
    )
{
    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size;
    uint8_t* buffer;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buffer);
    if (m_crypto->Encrypt(
            other_enclave_pem_key->buffer,
            m_enclave_config->enclave_secret_data,
            ENCLAVE_SECRET_DATA_SIZE,
            encrypted_data_buffer,
            &encrypted_data_size) == false)
    {
        TRACE_ENCLAVE("enclave: generate_encrypted_message failed");
        goto exit;
    }

    buffer = (uint8_t*)malloc(encrypted_data_size);
    if (buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying host_buffer failed, out of memory");
        goto exit;
    }
    memcpy(buffer, encrypted_data_buffer, encrypted_data_size);
    TRACE_ENCLAVE(
        "enclave: generate_encrypted_message: encrypted_data_size = %ld",
        encrypted_data_size);

    message->data = buffer;
    message->size = encrypted_data_size;

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encrypted_message(message_t* message)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(message->data, message->size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data.
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        TRACE_ENCLAVE("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
            if (m_enclave_config->enclave_secret_data[i] != data[i])
            {
                printf(
                    "Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_enclave_config->enclave_secret_data[i],
                    data[i]);
                ret = 1;
                break;
            }
        }
        printf("\n");
    }
    else
    {
        TRACE_ENCLAVE("Encalve:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    TRACE_ENCLAVE("Decrypted data matches with the enclave internal secret "
                  "data: descryption validation succeeded");
    ret = 0;
exit:
    return ret;
}



int  ecall_dispatcher::HotMsg_requestOCall( HotMsg* hotMsg, int dataID, void *data ) {
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    int data_index = dataID % (MAX_QUEUE_LENGTH - 1);
    //Request call
    while( true ) {
        HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[data_index];
        __sgx_spin_lock( &data_ptr->spinlock );
        if( data_ptr-> isRead == true ) {
            data_ptr-> isRead  = false;
            data_ptr->data = data;
            __sgx_spin_unlock( &data_ptr->spinlock );
            break;
        }
        else
            __sgx_spin_unlock( &data_ptr->spinlock );

        numRetries++;
        // if( numRetries > MAX_RETRIES ){
        //     printf("exceeded tries\n");
        //     sgx_spin_unlock( &data_ptr->spinlock );
        //     return -1;
        // }

        for( i = 0; i<3; ++i)
            _mm_sleep();
    }

    return numRetries;
}


void ecall_dispatcher::put_capsule(std::string data){
    OcallParams* args = (OcallParams*)oe_host_malloc(sizeof(OcallParams)); 
    args->ocall_id = OCALL_PUT;
    //args->data = data; //new capsule_pdu(); 
    CapsulePDU pdu = CapsulePDU(data, m_name, m_name, m_crypto);
    void* ptr_to_msg = pdu.to_untrusted_string();
    args->data = ptr_to_msg;
    args->data_size = pdu.get_payload_size();
    HotMsg_requestOCall( ocall_circular_buffer, requestedCallID++, args);
}

void ecall_dispatcher::put_ocall(std::string data){
    OcallParams* args = (OcallParams*)oe_host_malloc(sizeof(OcallParams)); 
    args->ocall_id = OCALL_PUT;
    //args->data = data; //new capsule_pdu(); 
    void* ret = oe_host_malloc(data.size());
    memcpy(ret, data.c_str(), data.size());

    args->data = ret;
    args->data_size = data.size();
    HotMsg_requestOCall( ocall_circular_buffer, requestedCallID++, args);
}



void ecall_dispatcher::put_advertisement(pem_key_t* pem_key,
        evidence_t* evidence){
    OcallParams* args = (OcallParams*)oe_host_malloc(sizeof(OcallParams)); 
    args->ocall_id = OCALL_PUT;
    CapsuleAdvertise pdu = CapsuleAdvertise(evidence, pem_key );
    this->m_name = pdu.get_my_hash();
    void* ptr_to_msg = pdu.to_untrusted_string();
    printf("the untrusted string is: %s", ptr_to_msg);
    args->data = ptr_to_msg;
    args->data_size = pdu.get_payload_size();
    HotMsg_requestOCall( ocall_circular_buffer, requestedCallID++, args);
}


// recv-ed packet handling 
int  ecall_dispatcher::EnclaveMsgStartResponder( HotMsg *hotMsg )
{
    TRACE_ENCLAVE("[EnclaveMsgStartResponder] started");
    // gdp_switch* proc_pkt_role = new gdp_switch(this);
    gdp_router* proc_pkt_role = new gdp_router(this);
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
            EcallParams * args = (EcallParams*) data_ptr->data;
            printf("[EnclaveMsgStartResponder] id is: %d\n",dataID);
            printf("[EnclaveMsgStartResponder] data is: %s\n", args->data);
            std::string s((char*)args->data, args->data_size);
            proc_pkt_role->proc_packet(s);
            data_ptr->data = 0;
        }

        data_ptr->isRead      = true;
        __sgx_spin_unlock( &data_ptr->spinlock );
        dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
        for( i = 0; i<3; ++i)
            _mm_pause();
    }
    return 0;
  }


void test_js(){
    duk_context *ctx = duk_create_heap_default();
    //duk_init_mem_interface(ctx); 
    duk_eval_string(ctx, "1+1;");
}