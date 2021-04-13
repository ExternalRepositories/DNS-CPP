/**
 *  Stress.cpp
 *
 *  Program to do a crazy amount of lookups to see if the library can
 *  keep up with this.
 *
 *  @author Emiel Bruijntjes <emiel.bruijntjes@copernica.com>
 *  @copyright 2021 Copernica BV
 */

/**
 *  Dependencies
 */
#include <dnscpp.h>
#include <iostream>
#include <ev.h>
#include <dnscpp/libev.h>
#include <math.h>
#include <fstream>
#include <iomanip>
#include <unistd.h>

/**
 *  The handler class
 */
struct MyHandler final : public DNS::Handler
{
    virtual void onResolved(const DNS::Operation *operation, const DNS::Response &response) override
    {
        std::cerr << "got response\n";
    }

    virtual void onFailure(const DNS::Operation *operation, int rcode) override
    {
        std::cerr << "got failure\n";
    }

    virtual void onTimeout(const DNS::Operation *operation) override
    {
        std::cerr << "got timeout\n";
    }
};

std::vector<std::string> readDomainList(const char *filename)
{
    std::vector<std::string> result;
    std::ifstream domainlist(filename);
    if (!domainlist) throw std::runtime_error("cannot open file");
    std::string line;
    while (std::getline(domainlist, line))
    {
        if (line.empty()) continue;
        result.push_back(line);
    }
    return result;
}

class MockNameServer final : public DNS::Monitor
{
    int _fd = -1;
    void *_identifier = nullptr;
    DNS::Loop *_loop = nullptr;

#define BUFSIZE 4 * 1024

    std::array<unsigned char, BUFSIZE> _receiveBuffer;
    std::array<unsigned char, BUFSIZE> _sendBuffer;

public:
    MockNameServer(DNS::Loop *loop, const DNS::Ip &ip) : _loop(loop)
    {
        // try to open it (note that we do not set the NONBLOCK option, because we have not implemented
        // buffering for the sendto() call (this could be a future optimization)
        _fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        // check for success
        if (_fd < 0) throw std::runtime_error("unable to open socket");
        sockaddr_in endpoint;
        memset(&endpoint, 0, sizeof(sockaddr_in));
        endpoint.sin_family = AF_INET;
        memcpy(&endpoint.sin_addr, ip.data(), sizeof(endpoint.sin_addr));
        endpoint.sin_port = htons(53);
        if (bind(_fd, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(sockaddr_in)))
        {
            perror("failed to bind socket");
            exit(1);
        }
        static const int bufsize = BUFSIZE;
        setsockopt(_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, 4);
        setsockopt(_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, 4);
        // we want to be notified when the socket receives data
        _identifier = _loop->add(_fd, 1, this);
    }

    /**
     *  Notify the monitor that the event that the monitor was watching
     *  for (for example activity on a filedescriptor or a timeout) has
     *  happened or has expired
     */
    virtual void notify() override
    {
        std::cerr << "got notified\n";
        // structure will hold the source address (we use an ipv6 struct because that is also big enough for ipv4)
        struct sockaddr_in6 from;
        socklen_t fromlen = sizeof(from);
        ssize_t bytes = 0;
        while (true)
        {
            bytes = recvfrom(_fd, _receiveBuffer.data(), _receiveBuffer.size(), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
            if (bytes == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    errno = 0;
                    return;
                }
                perror("error calling recfrom");
                exit(1);
            }
            else if (bytes == 0)
            {
                return;
            }
            else
            {
                // parse the address
                DNS::Ip ip(from);

                std::cerr << "got packet from " << ip << '\n';

                if (bytes < HFIXEDSZ + QFIXEDSZ)
                {
                    std::cerr << "haven't read enough bytes for query\n";
                }
                else
                {
                    const HEADER *header = reinterpret_cast<const HEADER*>(_receiveBuffer.data());
                    std::cerr
                        << "query id: " << ntohs(header->id)
                        << "\nopcode: " << ntohl(header->opcode)
                        << "\nrecursion desired: " << static_cast<bool>(header->rd)
                        << "\nquestion count: " << ntohs(header->qdcount)
                        << '\n';
                }
                std::copy(_receiveBuffer.begin(), _receiveBuffer.begin() + bytes, _sendBuffer.data());

                sendto(_fd, _sendBuffer.data(), bytes, 0, reinterpret_cast<const sockaddr*>(ip.data()), ip.size());
            }
        }
    }

    ~MockNameServer() noexcept { stop(); }

    void stop()
    {
        if (!_identifier) return;
        _loop->remove(_identifier, _fd, this);
        _identifier = nullptr;
        if (close(_fd)) perror("unable to close filedescriptor");
        _fd = -1;
    }
};

/**
 *  Main procedure
 *  @return int
 */
int main(int argc, char **argv)
{
    // the event loop
    struct ev_loop *loop = EV_DEFAULT;

    // wrap the loop to make it accessible by dns-cpp
    DNS::LibEv myloop(loop);

    const DNS::ResolvConf settings("./resolv.conf");

    MockNameServer mocknameserver(&myloop, settings.nameserver(0));

    // create a dns context
    DNS::Context context(&myloop, settings);

    const double timeout = 3.0;

    context.buffersize(4 * 1024); // size of the input buffer (high lowers risk of package loss)
    context.interval(timeout);    // number of seconds until the datagram is retried (possibly to next server) (this does not cancel previous requests)
    context.attempts(1);          // number of attempts until failure / number of datagrams to send at most
    context.capacity(10);         // max number of simultaneous lookups per dns-context (high increases speed but also risk of package-loss)
    context.timeout(timeout);     // time to wait for a response after the _last_ attempt

    // handler for the lookups
    MyHandler handler;

    context.query("general-kenobi.com", ns_t_a, &handler);

    // run the event loop
    ev_run(loop);

    // done
    return 0;
}

