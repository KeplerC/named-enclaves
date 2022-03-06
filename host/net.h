
#ifndef __HOST_NET_H
#define __HOST_NET_H
#include "zmq.hpp"
#include <string>
class Enclave_Entity;


class NetworkClient {

public:
    NetworkClient(Enclave_Entity* enclave);
    void run(); 

private: 
    zmq::message_t string_to_message(const std::string& s);
    std::string message_to_string(const zmq::message_t& message);
    std::string recv_string(zmq::socket_t* socket);
    void send_string(const std::string& s, zmq::socket_t* socket);

private:
    std::string local_proxy_ip = "localhost";
    std::string local_proxy_port = "5005";
    Enclave_Entity* m_enclave; 
};

#endif