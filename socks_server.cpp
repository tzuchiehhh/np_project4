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

struct Message {
    string S_IP;
    unsigned short S_PORT;
    string D_IP;
    string D_PORT;
    string Command;
    string Reply;
};

struct socks4_reply {
    int VN;
    // 90: request granted; 91: request rejected or failed
    int CD;
    string DSTPORT;
    string DSTIP;
};

class Bind
    : public enable_shared_from_this<Bind> {
   public:
    Bind(tcp::socket client_socket, tcp::socket server_socket, boost::asio::io_context &io_context)
        : client_socket(move(client_socket)), server_socket(move(server_socket)), acceptor(io_context, tcp::endpoint(tcp::v4(), 0)) {
        memset(client_buffer, 0x00, max_length);
        memset(server_buffer, 0x00, max_length);
        dstport = acceptor.local_endpoint().port();
    }

    void start() {
        bind_reply(false);
    }

   private:
    tcp::socket client_socket;
    tcp::socket server_socket;
    tcp::acceptor acceptor;
    enum { max_length = 10240 };
    unsigned char client_buffer[max_length];
    unsigned char server_buffer[max_length];
    unsigned short dstport;

    void bind_reply(bool bind) {
        auto self(shared_from_this());
        unsigned char p1 = dstport / 256;
        unsigned char p2 = dstport % 256;
        unsigned char reply[8] = {0, 90, p1, p2, 0, 0, 0, 0};
        boost::asio::async_write(client_socket, boost::asio::buffer(reply, 8), [this, self, bind](boost::system::error_code ec, size_t) {
            if (!ec) {
                if (bind == false) {
                    do_accept();
                } else {
                    read_client();
                    read_server();
                }
            }
        });
    }

    void do_accept() {
        auto self(shared_from_this());
        acceptor.async_accept(server_socket, [this, self](boost::system::error_code ec) {
            if (!ec) {
                bind_reply(true);
                acceptor.close();
            }
        });
    }

    // get data from client
    void read_client() {
        auto self(shared_from_this());
        client_socket.async_read_some(boost::asio::buffer(client_buffer, max_length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                write_server(length);
            } else if (ec == boost::asio::error::eof) {
                boost::system::error_code ect;
                client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ect);
                server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ect);
            } else {
                read_client();
            }
        });
    }

    // forward data to server
    void write_server(size_t length) {
        auto self(shared_from_this());
        boost::asio::async_write(server_socket, boost::asio::buffer(client_buffer, length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                read_client();
            } else {
                // client_socket.close();
            }
        });
    }

    // get data from server
    void read_server() {
        auto self(shared_from_this());
        server_socket.async_read_some(boost::asio::buffer(server_buffer, max_length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                write_client(length);
            } else if (ec == boost::asio::error::eof) {
                boost::system::error_code ect;

                server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ect);
                client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ect);
            } else {
                read_server();
            }
        });
    }

    // forward data to client
    void write_client(size_t length) {
        auto self(shared_from_this());
        boost::asio::async_write(client_socket, boost::asio::buffer(server_buffer, length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                read_server();
            } else {
                // client_socket.close();
            }
        });
    }
};

class Connect
    : public enable_shared_from_this<Connect> {
   public:
    Connect(tcp::socket client_socket, tcp::socket server_socket, tcp::endpoint endpoint)
        : client_socket(move(client_socket)), server_socket(move(server_socket)), endpoint(endpoint) {
        memset(client_buffer, 0x00, max_length);
        memset(server_buffer, 0x00, max_length);
    }
    void start() {
        auto self(shared_from_this());
        server_socket.async_connect(
            endpoint,
            [this, self](const boost::system::error_code &ec) {
                if (!ec) {
                    connect_reply();
                }
            });
    }

   private:
    tcp::socket client_socket;
    tcp::socket server_socket;
    tcp::endpoint endpoint;
    enum { max_length = 10240 };
    unsigned char client_buffer[max_length];
    unsigned char server_buffer[max_length];

    void connect_reply() {
        auto self(shared_from_this());
        unsigned char reply[8] = {0, 90, 0, 0, 0, 0, 0, 0};
        boost::asio::async_write(
            client_socket, boost::asio::buffer(reply, 8), [this, self](boost::system::error_code ec, size_t) {
                if (!ec) {
                    read_client();
                    read_server();
                }
            });
    }

    // get data from client
    void read_client() {
        auto self(shared_from_this());
        client_socket.async_read_some(boost::asio::buffer(client_buffer, max_length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                write_server(length);
            } else if (ec == boost::asio::error::eof) {
                boost::system::error_code ect;
                client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ect);
                server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ect);
            } else {
                read_client();
            }
        });
    }

    // forward data to server
    void write_server(size_t length) {
        auto self(shared_from_this());
        boost::asio::async_write(server_socket, boost::asio::buffer(client_buffer, length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                read_client();
            } else {
                // client_socket.close();
            }
        });
    }

    // get data from server
    void read_server() {
        auto self(shared_from_this());
        server_socket.async_read_some(boost::asio::buffer(server_buffer, max_length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                write_client(length);
            } else if (ec == boost::asio::error::eof) {
                boost::system::error_code ect;

                server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ect);
                client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ect);
            } else {
                read_server();
            }
        });
    }

    // forward data to client
    void write_client(size_t length) {
        auto self(shared_from_this());
        boost::asio::async_write(client_socket, boost::asio::buffer(server_buffer, length), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                read_server();
            } else {
                // client_socket.close();
            }
        });
    }
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
    Message message;

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
                do_connection();
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

    void do_connection() {
        string host;
        if (request.DOMAIN_NAME != "") {
            host = request.DOMAIN_NAME;
        } else {
            host = request.DSTIP;
        }

        tcp::socket server_socket(io_context);
        tcp::resolver resolver(io_context);
        tcp::resolver::query query(host, request.DSTPORT);
        tcp::resolver::iterator iter = resolver.resolve(query);
        tcp::endpoint endpoint = iter->endpoint();

        message.S_IP = client_socket.remote_endpoint().address().to_string();
        message.S_PORT = client_socket.remote_endpoint().port();
        message.D_IP = endpoint.address().to_string();
        message.D_PORT = request.DSTPORT;

        // connect
        if (request.CD == 1) {
            message.Command = "CONNECT";
            message.Reply = "Accept";
            show_message();
            make_shared<Connect>(move(client_socket), move(server_socket), endpoint)->start();
        }
        // Bind
        else if (request.CD == 2) {
            message.Command = "Bind";
            message.Reply = "Accept";
            show_message();
            make_shared<Bind>(move(client_socket), move(server_socket), io_context)->start();
        }
    }

    void show_message() {
        cout << "<S_IP>: " << message.S_IP << endl;
        cout << "<S_PORT>: " << message.S_PORT << endl;
        cout << "<D_IP>: " << message.D_IP << endl;
        cout << "<D_PORT>: " << message.D_PORT << endl;
        cout << "<Command>: " << message.Command << endl;
        cout << "<Reply>: " << message.Reply << endl;
        cout << endl;
    }

    // void send_reject() {
    //     auto self(shared_from_this());
    //     unsigned char reply[8] = {0, 91, 0, 0, 0, 0, 0, 0};
    //     memcpy(data_, reply, 8);
    //     boost::asio::async_write(client_socket, boost::asio::buffer(data_, 8), [this, self](boost::system::error_code ec, size_t /*length*/) {
    //         if (!ec) {
    //             client_socket.close();
    //         }
    //     });
    // }
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