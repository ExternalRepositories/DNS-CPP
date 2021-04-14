/**
 *  Udp.h
 *
 *  Internal class that implements a UDP socket over which messages
 *  can be sent to nameservers. You normally do not have to construct
 *  this class in user space, it is used internally by the Context class.
 *
 *  @author Emiel Bruijntjes <emiel.bruijntjes@copernica.com>
 *  @copyright 2020 - 2021 Copernica BV
 */

/**
 *  Include guard
 */
#pragma once

/**
 *  Dependencies
 */
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <sys/socket.h>
#include "monitor.h"
#include <list>
#include <string>

/**
 *  Begin of namespace
 */
namespace DNS {

/**
 *  Forward declarations
 */
class Core;
class Query;
class Loop;
class Ip;
class Response;
class Processor;

/**
 *  Class definition
 */
class Udp : private Monitor
{
public:
    /**
     *  Helper method to set an integer socket option
     *  @param  optname
     *  @param  optval
     */
    int setintopt(int optname, int32_t optval);
    
private:
    /**
     *  event loop
     *  @var Loop*
     */
    Loop *_loop;
    
    /**
     *  The filedescriptor of the socket
     *  @var int
     */
    int _fd = -1;
    
    /**
     *  User space identifier of this monitor
     *  @var void *
     */
    void *_identifier = nullptr;

    /**
     *  The object that is interested in handling responses
     *  @var Processor*
     */
    Processor *_processor;
    
    /**
     *  Method that is called from user-space when the socket becomes readable.
     */
    virtual void notify() override;
    
    /**
     *  Send a query to a certain nameserver
     *  @param  address     target address
     *  @param  size        size of the address
     *  @param  query       query to send
     *  @return bool
     */
    bool send(const struct sockaddr *address, size_t size, const Query &query);

    /**
     *  Open the socket (this is optional, the socket is automatically opened when you start sending to it)
     *  @param  version
     *  @param  buffersize
     *  @return bool
     */
    bool open(int version, int buffersize);

public:
    /**
     *  Constructor
     *  @param  loop        event loop
     *  @param  Processor    object that will receive all incoming responses
     *  @throws std::runtime_error
     */
    Udp(Loop *loop, Processor *Processor);
    
    /**
     *  No copying
     *  @param  that
     */
    Udp(const Udp &that) = delete;
        
    /**
     *  Destructor
     */
    virtual ~Udp();

    /**
     *  Send a query to the socket
     *  Watch out: you need to be consistent in calling this with either ipv4 or ipv6 addresses
     *  @param  ip      IP address of the target nameserver
     *  @param  query   the query to send
     *  @param  buffersize
     *  @return bool
     */
    bool send(const Ip &ip, const Query &query, int buffersize);

    /**
     *  Close the socket (this is useful if you do not expect incoming data anymore)
     *  The socket will be automatically opened if you start sending to it
     *  @return bool
     */
    bool close();

    /**
     *  Is the socket now readable?
     *  @return bool
     */
    bool readable() const;
};
    
/**
 *  End of namespace
 */
}
