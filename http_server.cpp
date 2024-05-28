#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

using boost::asio::ip::tcp;
using namespace std;

boost::asio::io_context io_context;

class session
    : public std::enable_shared_from_this<session> {
public:
    session(tcp::socket socket)
        : socket_(std::move(socket)) {
    }

    void start() {
        do_read();
    }

private:
    tcp::socket socket_;
    enum { max_length = 1024 };
    char data_[max_length];
    string status_str = "HTTP/1.1 200 OK\n";
    string request_method;
    string request_uri;
    string query_string;
    string server_protocol;
    string http_host;
    string server_addr;
    string server_port;
    string remote_addr;
    string remote_port;
    string exec_command;

    void do_read() {
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
                                [this, self](boost::system::error_code ec, std::size_t length) {
                                    if (!ec) {
                                        parse_request();
                                        do_write(length);
                                    }
                                });
    }

    void do_write(std::size_t length) {
        auto self(shared_from_this());
        boost::asio::async_write(socket_, boost::asio::buffer(status_str, status_str.length()),
                                 [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec) {
                                         io_context.notify_fork(boost::asio::io_context::fork_prepare);
                                         int status;
                                         pid_t pid = fork();
                                         while (pid < 0) {
                                             wait(&status);
                                             pid = fork();
                                         }
                                         //  child
                                         if (pid == 0) {
                                             io_context.notify_fork(boost::asio::io_context::fork_child);

                                             set_env();
                                             dup2(socket_.native_handle(), STDIN_FILENO);
                                             dup2(socket_.native_handle(), STDOUT_FILENO);
                                             dup2(socket_.native_handle(), STDERR_FILENO);
                                             socket_.close();

                                             if (execlp(exec_command.c_str(), exec_command.c_str(), NULL) < 0) {
                                                 cout << "Content-type:text/html\r\n\r\n<h1>exec failed</h1>";
                                                 fflush(stdout);
                                             }

                                         }
                                         // parent process
                                         else {
                                             signal(SIGCHLD, SIG_IGN);
                                             io_context.notify_fork(boost::asio::io_context::fork_parent);
                                             socket_.close();
                                         }
                                     }
                                 });
    }

    void parse_request() {
        // cout << data_ << endl;
        string request = string(data_);
        stringstream request_ss(request);
        string header;
        getline(request_ss, header);
        stringstream header_ss(header);
        string request_uri_line;
        header_ss >> request_method >> request_uri_line >> server_protocol;
        stringstream request_uri_ss(request_uri_line);
        // cout<<request_uri_line<<endl;
        getline(request_uri_ss, request_uri, '?');
        getline(request_uri_ss, query_string);

        string header_host;
        getline(request_ss, header_host);
        stringstream host_ss(header_host);
        string tmp;
        host_ss >> tmp >> http_host;

        server_addr = socket_.local_endpoint().address().to_string();
        server_port = to_string(socket_.local_endpoint().port());
        remote_addr = socket_.remote_endpoint().address().to_string();
        remote_port = to_string(socket_.remote_endpoint().port());
        exec_command = boost::filesystem::current_path().string() + request_uri;
        cout<<exec_command<<endl;
        cout << "REQUEST_METHOD: " << request_method << endl;
        cout << "REQUEST_URI: " << request_uri << endl;
        cout << "QUERY_STRING: " << query_string << endl;
        cout << "SERVER_PROTOCOL: " << server_protocol << endl;
        cout << "HTTP_HOST: " << http_host << endl;
        cout << "SERVER_ADDR: " << server_addr << endl;
        cout << "SERVER_PORT: " << server_port << endl;
        cout << "REMOTE_ADDR: " << remote_addr << endl;
        cout << "REMOTE_PORT: " << remote_port << endl;
    }

    void set_env() {
        setenv("REQUEST_METHOD", request_method.c_str(), 1);
        setenv("REQUEST_URI", request_uri.c_str(), 1);
        setenv("QUERY_STRING", query_string.c_str(), 1);
        setenv("SERVER_PROTOCOL", server_protocol.c_str(), 1);
        setenv("HTTP_HOST", http_host.c_str(), 1);
        setenv("SERVER_ADDR", server_addr.c_str(), 1);
        setenv("SERVER_PORT", server_port.c_str(), 1);
        setenv("REMOTE_ADDR", remote_addr.c_str(), 1);
        setenv("REMOTE_PORT", remote_port.c_str(), 1);
    }
};

class server {
public:
    server(boost::asio::io_context &io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<session>(std::move(socket))->start();
                }

                do_accept();
            });
    }

    tcp::acceptor acceptor_;
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