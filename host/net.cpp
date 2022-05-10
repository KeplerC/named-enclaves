
#include "net.h"
#include "enclave_entity.h"
#include "log.h"
#include <random>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>  

NetworkClient::NetworkClient(Enclave_Entity* enclave){
    {
        m_enclave_entity = enclave; 

        int base_port = 3005;
        int range = 5205 - base_port + 1;
        m_port = rand() % range + base_port;

        TRACE_ENCLAVE("[NetworkClient] Initialized with port: %d", m_port);
    }
}


void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}


//thread polling from the network
void NetworkClient::run_message_receiver(){
    zmq::context_t context (1);
    // socket for join requests
    zmq::socket_t socket_recv (context, ZMQ_PULL);
    socket_recv.bind ("tcp://*:" + std::to_string(m_port));
    TRACE_ENCLAVE("[NetworkClient] Network Client thread started!");

    // to router
    zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_ptr -> connect ("tcp://" + std::string(NET_PROXY_IP) + ":" + std::string(NET_PROXY_PORT));

    std::vector<zmq::pollitem_t> pollitems = {
        { static_cast<void *>(socket_recv), 0, ZMQ_POLLIN, 0 },
    };

    while (true) {
        zmq::poll(pollitems.data(), pollitems.size(), 0);

        if (pollitems[0].revents & ZMQ_POLLIN){
            zmq::message_t* message = new zmq::message_t();
            socket_recv.recv(message);
            TRACE_ENCLAVE("[NetworkClient] Receive %s",message->data() );
            

            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();     

            /* Set up the key and iv. Do I need to say to not hard code these in a real application? :-) */

            /* A 256 bit key */
            unsigned char key[] = "01234567890123456789012345678901";

            /* A 128 bit IV */
            unsigned char iv[] = "0123456789012345";

            /* Message to be encrypted */
            unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";

            /* Some additional data to be authenticated */
            unsigned char aad[] = "Some AAD data";

            /* Buffer for ciphertext. Ensure the buffer is long enough for the
            * ciphertext which may be longer than the plaintext, dependant on the
            * algorithm and mode
            */
            unsigned char ciphertext[128];

            /* Buffer for the decrypted text */
            unsigned char decryptedtext[128];

            /* Buffer for the tag */
            unsigned char tag[16];

            int decryptedtext_len = 0, ciphertext_len = 0;

            // /* Encrypt the plaintext */
            // ciphertext_len = encrypt(plaintext, 80, aad, 14, key, iv, ciphertext, tag);

            // // /* Decrypt the ciphertext */
            // decryptedtext_len = decrypt(ciphertext, ciphertext_len, aad,14, tag, key, iv, decryptedtext);

            // /* Remove error strings */
            // ERR_free_strings();


            m_enclave_entity->ecall_send_to_enclave(message->data(), message->size());
            this->m_enclave_entity->dummy_ecall();
            
            // socket_ptr->send(*message);
        }
    }
}


void NetworkClient::send_to_proxy(zmq::message_t* msg){
    
    zmq::context_t context (1);
    // to router
    zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_ptr -> connect ("tcp://" + std::string(NET_PROXY_IP) + ":" + std::string(NET_PROXY_PORT));
    socket_ptr->send(*msg);

    TRACE_ENCLAVE("[NetworkClient] Send to Proxy: %s",msg->data() );
}

zmq::message_t NetworkClient::string_to_message(const std::string& s) {
    zmq::message_t msg(s.size());
    memcpy(msg.data(), s.c_str(), s.size());
    return msg;
}

std::string NetworkClient::message_to_string(const zmq::message_t& message) {
    return std::string(static_cast<const char*>(message.data()), message.size());
}

std::string NetworkClient::recv_string(zmq::socket_t* socket) {
    zmq::message_t message;
    socket->recv(&message);
    return this->message_to_string(message);
}
void NetworkClient::send_string(const std::string& s, zmq::socket_t* socket) {
    socket->send(string_to_message(s));
}