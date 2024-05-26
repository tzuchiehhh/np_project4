#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <utility>

using boost::asio::ip::tcp;
using namespace std;

struct socks4_request {
    int VN;
    int CD;
    string DSTPORT;
    string DSTIP;
    string USERID;
    string DOMAIN_NAME;
};

struct socks4_reply {
    int VN;
    // 90: request granted; 91: request rejected or failed
    int CD;
    string DSTPORT;
    string DSTIP;

};

class socks
    : public enable_shared_from_this<socks> {
   public:
    socks(tcp::socket socket, boost::asio::io_context &io_context)
        : client_socket(std::move(socket)), io_context(io_context) {
    }
    void start() {
        parse_request();
    }

   private:
    tcp::socket client_socket;
    enum { max_length = 10240 };
    unsigned char data_[max_length];
    boost::asio::io_context &io_context;

    socks4_request request;
    

    void parse_request() {
        auto self(shared_from_this());
        client_socket.async_read_some(boost::asio::buffer(data_, max_length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                request.VN = data_[0];
                request.CD = data_[1];
                request.DSTPORT = to_string(((int)data_[2] * 256) + (int)data_[3]);
                request.DSTIP = get_destination_ip();
                request.DOMAIN_NAME = get_domain_name(length);

                // cout<<to_string(request.VN)<<endl;
                // cout<<to_string(request.CD)<<endl;
                // cout<<request.DSTPORT<<endl;
                // cout<<request.DSTIP<<endl;
                // cout<<request.DOMAIN_NAME<<endl;

            }
        });
    }

    string get_destination_ip() {
        string dstip = "";
        for (int i = 4; i < 8; ++i) {
            dstip += to_string(data_[i]);
            if (i != 7) {
                dstip += ".";
            }
        }
        return dstip;
    }

    string get_domain_name(size_t length) {
        int idx1 = -1, idx2 = -1;
        string domain_name = "";
        for (size_t i = 8; i < length; i++) {
            if (data_[i] == 0x00) {
                if (idx1 == -1)
                    idx1 = i;
                else
                    idx2 = i;
            }
        }
        if (idx2 != -1) {
            for (int j = idx1 + 1; j < idx2; j++) {
                domain_name += data_[j];
            }
        }
        return domain_name;
    }

    
};

class server {
   public:
    tcp::acceptor acceptor_;
    boost::asio::io_context &io_context;

    server(boost::asio::io_context &io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), io_context(io_context) {
        do_accept();
    }

   private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    // fork
                    io_context.notify_fork(boost::asio::io_context::fork_prepare);
                    int status;
                    pid_t pid = fork();
                    while (pid < 0) {
                        wait(&status);
                        pid = fork();
                    }
                    // child
                    if (pid == 0) {
                        io_context.notify_fork(boost::asio::io_context::fork_child);
                        acceptor_.close();
                        make_shared<socks>(move(socket), io_context)->start();
                    }
                    // parent
                    else {
                        io_context.notify_fork(boost::asio::io_context::fork_parent);
                        signal(SIGCHLD, SIG_IGN);
                        socket.close();
                        do_accept();
                    }
                }

                do_accept();
            });
    }
};

int main(int argc, char *argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: async_tcp_echo_server <port>\n";
            return 1;
        }

        boost::asio::io_context io_context;

        server s(io_context, std::atoi(argv[1]));

        io_context.run();
    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}