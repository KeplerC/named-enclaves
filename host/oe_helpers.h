
#ifndef __OE_HELPERS_H
#define __OE_HELPERS_H



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

#endif 