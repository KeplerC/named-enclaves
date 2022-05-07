
#ifndef __HOST_NET_H
#define __HOST_NET_H
#include "zmq.hpp"
#include <string>
class Enclave_Entity;


class NetworkClient {

public:
    NetworkClient(Enclave_Entity* enclave);
    void run_message_receiver(); 
    void send_to_proxy(zmq::message_t* msg);

    int get_port(){
        return m_port;
    }

    std::string get_addr(){
        return "localhost:" + std::to_string(m_port);
    }

private: 
    zmq::message_t string_to_message(const std::string& s);
    std::string message_to_string(const zmq::message_t& message);
    std::string recv_string(zmq::socket_t* socket);
    void send_string(const std::string& s, zmq::socket_t* socket);


private:
    Enclave_Entity* m_enclave_entity; 
    int m_port; 
};

#endif