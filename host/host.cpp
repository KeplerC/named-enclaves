// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "attestation_u.h"
#include <thread>
#include <unistd.h>
#include "enclave_entity.h"
#include "oe_helpers.h"

const char* enclave_name = "HOST_UNTRUSTED";

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave_a = NULL;
    oe_enclave_t* enclave_b = NULL;
    message_t encrypted_message = {0};
    oe_result_t result = OE_OK;
    int ret = 1;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    oe_uuid_t* format_id = &sgx_remote_uuid;
    evidence_t evidence = {0};
    pem_key_t pem_key = {0};

    printf("Host: Creating two enclaves\n");
    enclave_a = create_enclave("./enclave/enclave_a.signed", flags);
    if (enclave_a == NULL)
    {
        printf("Enclave creation failed!\n");
    }
    enclave_b = create_enclave("./enclave/enclave_a.signed", flags);
    if (enclave_b == NULL)
    {
        printf("Enclave creation failed!\n");
    }
    

    auto ee = Enclave_Entity(enclave_a);
    sleep(1);

    generate_identity_report(format_id, "enclave_a", enclave_a, evidence, pem_key); 
    verify_identity_report(format_id, "enclave_b", enclave_b, evidence, pem_key); 


#ifdef __linux__
    // verify if SGX_AESM_ADDR is successfully set
    if (getenv("SGX_AESM_ADDR"))
    {
        printf("Host: environment variable SGX_AESM_ADDR is set\n");
    }
    else
    {
        printf("Host: environment variable SGX_AESM_ADDR is not set\n");
    }
#endif

    encrypted_message.data = NULL;

    printf("Host: Requesting encrypted message from 2nd enclave\n");
    result = generate_encrypted_message(enclave_b, &ret, &encrypted_message, &pem_key);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_encrypted_message failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Sending encrypted message to 1st enclave=====\n");
    result = process_encrypted_message(enclave_a, &ret, &encrypted_message);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "host process_encrypted_message failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }


    sleep(10);
    ret = 0;

exit:
    // Free host memory allocated by the enclave.
    printf("Host: Terminating everything on exit\n");
    if (encrypted_message.data)
        free(encrypted_message.data);
    if (evidence.buffer)
        free(evidence.buffer);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
