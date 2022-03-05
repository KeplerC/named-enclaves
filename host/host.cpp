// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "attestation_u.h"

// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_attestation_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

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

int attest_one_enclave_to_the_other(
    const oe_uuid_t* format_id,
    const char* attester_enclave_name,
    oe_enclave_t* attester_enclave,
    const char* verifier_enclave_name,
    oe_enclave_t* verifier_enclave)
{
    oe_result_t result = OE_OK;
    int ret = 1;
    format_settings_t format_settings = {0};
    evidence_t evidence = {0};
    pem_key_t pem_key = {0};

    printf(
        "\n\nHost: ********** Attest %s to %s **********\n\n",
        attester_enclave_name,
        verifier_enclave_name);

    printf("Host: Requesting %s format settings\n", verifier_enclave_name);
    result = get_enclave_format_settings(
        verifier_enclave, &ret, format_id, &format_settings);
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
    printf(
        "Host: %s's  public key: \n%s\n",
        attester_enclave_name,
        pem_key.buffer);

    printf(
        "Host: verify_evidence_and_set_public_key in %s\n",
        verifier_enclave_name);
    result = verify_evidence_and_set_public_key(
        verifier_enclave, &ret, format_id, &pem_key, &evidence);
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
    free(pem_key.buffer);
    free(evidence.buffer);
    free(format_settings.buffer);
    return ret;
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
        verifier_enclave, &ret, format_id, &pem_key, &evidence);
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

    /* Check argument count */
    if (argc != 4)
    {
        printf("Usage: %s <tee> ENCLAVE_PATH1 ENCLAVE_PATH2\n", argv[0]);
        printf("       where <tee> is one of:\n");
        printf("           sgxlocal  : for SGX local attestation\n");
        printf("           sgxremote : for SGX remote attestation\n");
        return 1;
    }

    printf("Host: Creating two enclaves\n");
    enclave_a = create_enclave("./enclave/enclave_a.signed", flags);
    if (enclave_a == NULL)
    {
        goto exit;
    }
    enclave_b = create_enclave("./enclave/enclave_a.signed", flags);
    if (enclave_b == NULL)
    {
        goto exit;
    }
    // ret = attest_one_enclave_to_the_other(
    // format_id, "enclave_a", enclave_a, "enclave_b", enclave_b);
    // if (ret)
    // {
    //     printf("Host: attestation failed with %d\n", ret);
    //     goto exit;
    // }

    
    generate_identity_report(format_id, "enclave_a", enclave_a, evidence, pem_key); 
        printf(
        "Host's  public key: \n%s\n",
        pem_key.buffer);

    verify_identity_report(format_id, "enclave_b", enclave_b, evidence, pem_key); 
    printf("Verification succeeds!\n");
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

    

    ret = 0;

exit:
    // Free host memory allocated by the enclave.
    free(encrypted_message.data);
    free(evidence.buffer);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
