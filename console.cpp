#include <array>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <fstream>
#include <iostream>
#include <queue>
#include <string>
#include <tuple>
#include <vector>

using boost::asio::ip::tcp;
using namespace std;

boost::asio::io_context io_context;
string sock_server_host = "";
string sock_server_port = "";

class session
    : public std::enable_shared_from_this<session> {
   public:
    session(tcp::socket socket, tcp::endpoint endpoint, string index, string filename)
        : socket_(std::move(socket)), endpoint_(endpoint) {
        index_ = index;
        commands = read_file_commands(filename);
    }

    void start() {
        auto self(shared_from_this());
        if (sock_server_host != "" && sock_server_port != "") {
            // cout<<"proxy server"<<endl;
            tcp::resolver resolver(io_context);
            tcp::resolver::query query(sock_server_host, sock_server_port);
            tcp::resolver::iterator iter = resolver.resolve(query);
            tcp::endpoint proxy_endpoint = iter->endpoint();
            socket_.async_connect(proxy_endpoint, [this, self](boost::system::error_code ec) {
                if (!ec) {
                    send_request();
                }
            });

        } else {
            do_connect();
        }
    }

   private:
    tcp::socket socket_;
    tcp::endpoint endpoint_;
    enum { max_length = 10240 };
    char data_[max_length];
    string index_;
    queue<string> commands;

    void send_request() {
        // cout<<"send request"<<endl;
        auto self(shared_from_this());
        unsigned short dstport = endpoint_.port();
        unsigned char p1 = dstport / 256;
        unsigned char p2 = dstport % 256;

        string dstip = endpoint_.address().to_string();
        string ip_0, ip_1, ip_2, ip_3;
        stringstream ss(dstip);
        getline(ss, ip_0, '.');
        getline(ss, ip_1, '.');
        getline(ss, ip_2, '.');
        getline(ss, ip_3, '.');

        unsigned char request[9] = {4, 1, p1, p2, (unsigned char)stoi(ip_0), (unsigned char)stoi(ip_1), (unsigned char)stoi(ip_2), (unsigned char)stoi(ip_3), 0};
        socket_.async_write_some(boost::asio::buffer(request, 9), [this, self](boost::system::error_code ec, size_t length) {
            if (!ec) {
                recv_reply();
            } else {
                // cout << "send_request error" << endl;
                cout << ec.message() << endl;
            }
        });
    }

    void recv_reply() {
        // cout<<"recv reply"<<endl;
        auto self(shared_from_this());
        socket_.async_read_some(
            boost::asio::buffer(data_, max_length), [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    memset(data_, '\0', max_length);
                    // cout<<"success reply do read"<<endl;
                    do_read();
                } else {
                    // cout << "recv_reply error" << endl;
                    cout << ec.message() << endl;
                }
            });
    }

    void do_connect() {
        auto self(shared_from_this());
        socket_.async_connect(endpoint_, [this, self](boost::system::error_code ec) {
            if (!ec) {
                do_read();
            }
        });
    }

    void do_read() {
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
                                [this, self](boost::system::error_code ec, std::size_t length) {
                                    if (!ec) {
                                        //   cout<<"do_read!!!!!!!!!!!!!!!!!!!"<<endl;
                                        string res = string(data_);
                                        // cout << res << endl;
                                        memset(data_, '\0', max_length);
                                        output_shell(res);
                                        if (res.find("%") != std::string::npos) {
                                            // cout << "find %!!!!!!!!!!!!!!!!!!!!!!" << endl;
                                            do_write();
                                        } else {
                                            do_read();
                                        }
                                    }
                                });
    }

    void do_write() {
        auto self(shared_from_this());
        string c_command = commands.front();
        commands.pop();
        char output[max_length];
        strcpy(output, c_command.c_str());
        output_command(c_command);

        boost::asio::async_write(socket_, boost::asio::buffer(output, strlen(output)),
                                 [this, self](boost::system::error_code ec, std::size_t) {
                                     if (!ec) {
                                         do_read();
                                     }
                                 });
    }

    queue<string> read_file_commands(string filename) {
        queue<string> commands;
        string line;
        ifstream file;
        file.open(filename);
        while (getline(file, line)) {
            commands.push(line + "\n");
        }
        file.close();
        return commands;
    }

    void output_shell(string str) {
        escape(str);
        cout << "<script>document.getElementById(\'s" + index_ + "\').innerHTML += \'" + str + "\';</script>" << flush;
    }

    void output_command(string str) {
        escape(str);
        cout << "<script>document.getElementById(\'s" + index_ + "\').innerHTML += \'<b>" + str + "</b>\';</script>" << flush;
    }
    void escape(string &str) {
        boost::replace_all(str, "&", "&amp;");
        boost::replace_all(str, "\"", "&quot;");
        boost::replace_all(str, "\'", "&apos;");
        boost::replace_all(str, "<", "&lt;");
        boost::replace_all(str, ">", "&gt;");
        boost::replace_all(str, "\n", "&NewLine;");
        boost::replace_all(str, "\r", "");
    }
};

vector<tuple<string, string, string>> parse_query_string() {
    string query_string = string(getenv("QUERY_STRING"));
    // cout << query_string << endl
    //      << endl;
    stringstream ss(query_string);
    string token;
    // 0: hostname; 1: port; 2:file
    vector<tuple<string, string, string>> clients;
    for (int i = 0; i < 5; i++) {
        string hostname;
        string port;
        string filename;
        getline(ss, hostname, '&');
        getline(ss, port, '&');
        getline(ss, filename, '&');
        hostname = hostname.substr(3);
        port = port.substr(3);
        filename = filename.substr(3);

        if (hostname.length() != 0 && port.length() != 0 && filename.length() != 0) {
            clients.push_back({hostname, port, "test_case/" + filename});
        }
    }

    getline(ss, sock_server_host, '&');
    getline(ss, sock_server_port, '&');
    sock_server_host = sock_server_host.substr(3);
    sock_server_port = sock_server_port.substr(3);

    for (int i = 0; i < clients.size(); i++) {
        // cout << "hostname: " << get<0>(clients[i]) << " port: " << get<1>(clients[i]) << " file: " << get<2>(clients[i]) << endl;
    }
    // sock_server_host = "np.local";
    // cout << "sock_server_host: "<<sock_server_host << endl;
    // cout << "sock_server_port: "<<sock_server_port << endl;

    return clients;
}

void connect_to_server(vector<tuple<string, string, string>> clients) {
    for (int i = 0; i < clients.size(); ++i) {
        // tcp::resolver::query query(get<0>(clients[i]), get<1>(clients[i]));
        // tcp::socket socket(io_context);

        tcp::socket socket(io_context);
        tcp::resolver resolver(io_context);
        tcp::resolver::query query(get<0>(clients[i]), get<1>(clients[i]));
        tcp::resolver::iterator iter = resolver.resolve(query);
        tcp::endpoint endpoint = iter->endpoint();
        make_shared<session>(move(socket), endpoint, to_string(i), get<2>(clients[i]))->start();
    }
}

void print_html(vector<tuple<string, string, string>> clients) {
    cout << "Content-type: text/html\r\n\r\n";
    cout << "<!DOCTYPE html>\
<html lang=\"en\">\
  <head>\
    <meta charset=\"UTF-8\" />\
    <title>NP Project 4 Sample Console</title>\
    <link\
      rel=\"stylesheet\"\
      href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css\"\
      integrity=\"sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2\"\
      crossorigin=\"anonymous\"\
    />\
    <link\
      href=\"https://fonts.googleapis.com/css?family=Source+Code+Pro\"\
      rel=\"stylesheet\"\
    />\
    <link\
      rel=\"icon\"\
      type=\"image/png\"\
      href=\"https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678068-terminal-512.png\"\
    />\
    <style>\
      * {\
        font-family: 'Source Code Pro', monospace;\
        font-size: 1rem !important;\
      }\
      body {\
        background-color: #212529;\
      }\
      pre {\
        color: #cccccc;\
      }\
      b {\
        color: #01b468;\
      }\
    </style>\
  </head>\
  <body>\
    <table class=\"table table-dark table-bordered\">\
      <thead>\
        <tr>";
    for (int i = 0; i < clients.size(); i++) {
        cout << "<th scope=\"col\">" << get<0>(clients[i]) << ":" << get<1>(clients[i]) << "</th>";
    }
    cout << "         </tr>\
                </thead>\
                <tbody>\
                    <tr>";
    for (int i = 0; i < clients.size(); i++) {
        cout << "<td><pre id=\"s" + to_string(i) + "\" class=\"mb-0\"></pre></td>";
    }
    cout << "         </tr>\
                </tbody>\
            </table>\
        </body>\
    </html>";
}

int main() {
    try {
        vector<tuple<string, string, string>> clients = parse_query_string();
        print_html(clients);
        connect_to_server(clients);
        io_context.run();
    } catch (exception &e) {
        cerr << e.what() << endl;
    }
}
