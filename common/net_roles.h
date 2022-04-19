#ifndef NET_ROLE_H
#define NET_ROLE_H
#include <string>
#include "rib.h"


class net_role
{
public:
    net_role(ecall_dispatcher* dispatcher){
        m_dispatcher = dispatcher;
    }
    void proc_packet(std::string pkt){
        auto splitted = split(pkt, ",,,");
        if(splitted[0] == "ADV"){
            proc_adv(splitted, pkt); 
        }
        else if(splitted[0] == "QUERY") {
            proc_query(splitted); 
        }
    }
    virtual void proc_adv(std::vector<std::string> splitted, std::string advertisement) = 0;
    virtual void proc_query(std::vector<std::string> splitted) = 0;
    virtual void proc_data(std::vector<std::string> splitted) = 0;
protected:
    ecall_dispatcher* m_dispatcher; 
    string ToHex(const string& s, bool upper_case /* = true */)
    {
        ostringstream ret;

        for (string::size_type i = 0; i < s.length(); ++i)
            ret << std::hex << std::setfill('0') << std::setw(1) << (upper_case ? std::uppercase : std::nouppercase) <<  (unsigned int)(unsigned char)s[i];
        return ret.str();
    }

    std::vector<std::string> split(std::string const &str, const std::string delim
                )
    {
        size_t start;
        size_t end = 0;
        std::vector<std::string> out;
    
        while ((start = str.find_first_not_of(delim, end)) != std::string::npos)
        {
            end = str.find(delim, start);
            out.push_back(str.substr(start, end - start));
        }
        return out; 
    }
};


class gdp_router: public net_role
{
public:
    gdp_router(ecall_dispatcher* dispatcher) : net_role(dispatcher) {} 
    
    void proc_adv(std::vector<std::string> splitted, std::string advertisement) override {
        std::string adv_hash = ToHex(splitted[splitted.size() -1], 0);
        std::cout << "Receive Advertisement" << adv_hash << std::endl;
        this->m_rib.put(adv_hash, advertisement);
    }
    void proc_query(std::vector<std::string> splitted) override {
        //std::string query_hash = ToHex(splitted[splitted.size() -1], 0);
        std::string query_hash = splitted[splitted.size() -1];
        std::cout << "Receive QUERY " << query_hash << std::endl;
        auto ret = this->m_rib.get(query_hash);
        if(ret != "")
            m_dispatcher->put_ocall(ret);
        else
            TRACE_ENCLAVE("[EnclaveMsgStartResponder] Cannot find RIB entry");
    }
    void proc_data(std::vector<std::string> splitted) override{

    }
private: 
    RIB m_rib; 
};

#endif 