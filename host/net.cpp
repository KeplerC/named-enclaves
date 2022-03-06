
#include "net.h"
#include "enclave_entity.h"


NetworkClient::NetworkClient(Enclave_Entity* enclave){
    {
        m_enclave = enclave; 
        m_enclave -> run();
    }
}



void NetworkClient::run(){
    zmq::context_t context (1);
    // socket for join requests
    zmq::socket_t socket_recv (context, ZMQ_PULL);
    socket_recv.bind ("tcp://*:" + std::to_string(NET_CLIENT_RECV_PORT));

    std::vector<zmq::pollitem_t> pollitems = {
        { static_cast<void *>(socket_recv), 0, ZMQ_POLLIN, 0 },
    };

    while (true) {
        zmq::poll(pollitems.data(), pollitems.size(), 0);

        if (pollitems[0].revents & ZMQ_POLLIN){
            //Get the address
            std::string msg = this->recv_string(&socket_recv);
            
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