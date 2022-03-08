
#include "net.h"
#include "enclave_entity.h"
#include "log.h"

NetworkClient::NetworkClient(Enclave_Entity* enclave){
    {
        m_enclave_entity = enclave; 
    }
}


//thread polling from the network
void NetworkClient::run_message_receiver(){
    zmq::context_t context (1);
    // socket for join requests
    zmq::socket_t socket_recv (context, ZMQ_PULL);
    socket_recv.bind ("tcp://*:" + std::to_string(NET_CLIENT_RECV_PORT));
    TRACE_ENCLAVE("[NetworkClient] Network Client thread started!");

    std::vector<zmq::pollitem_t> pollitems = {
        { static_cast<void *>(socket_recv), 0, ZMQ_POLLIN, 0 },
    };

    while (true) {
        zmq::poll(pollitems.data(), pollitems.size(), 0);

        if (pollitems[0].revents & ZMQ_POLLIN){
            //Get the address
            //std::string msg = this->recv_string(&socket_recv);
            //TRACE_ENCLAVE("[NetworkClient] Received Data to send to enclave: %s, %d", msg.c_str(), msg.size());
            zmq::message_t message;
            socket_recv.recv(&message);
            m_enclave_entity->ecall_send_to_enclave(message.data(), message.size());
        }
    }
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