/**
 *  RemoteLookup.cpp
 *  
 *  Implementation file for the RemoteLookup class
 * 
 *  @author Emiel Bruijntjes <emiel.bruijntjes@copernica.com>
 *  @copyright 2020 Copernica BV
 */

/**
 *  Dependencies
 */
#include "remotelookup.h"
#include "connection.h"
#include "../include/dnscpp/core.h"
#include "../include/dnscpp/response.h"
#include "../include/dnscpp/answer.h"
#include "../include/dnscpp/handler.h"
#include "../include/dnscpp/question.h"
#include "fakeresponse.h"
#include <cassert>

/**
 *  Begin of namespace
 */
namespace DNS {

/**
 *  Constructor
 *  @param  core        dns core object
 *  @param  domain      the domain of the lookup
 *  @param  type        the type of the request
 *  @param  bits        bits to include
 *  @param  handler     user space object
 */
RemoteLookup::RemoteLookup(Core *core, const char *domain, ns_type type, const Bits &bits, DNS::Handler *handler) : 
    Lookup(handler, ns_o_query, domain, type, bits), _core(core), _id(rand()) {}

/**
 *  Destructor
 */
RemoteLookup::~RemoteLookup()
{
    cleanup();
}

/**
 *  How many credits are left (meaning: how many datagrams do we still have to send?)
 *  @return size_t      number of attempts
 */
size_t RemoteLookup::credits() const
{
    // precondition check
    assert(_core->attempts() >= _count);

    // number of attempts left
    return _core->attempts() - _count;
}

/**
 *  Unsubscribe from all inbound UDP sockets
 */
void RemoteLookup::unsubscribe()
{
    // unsubscribe from the UDP sockets
    for (const auto &subscription : _subscriptions)
    {
        // this is a pair
        subscription.first->unsubscribe(this, subscription.second, _query.id());
    }
    
    // we have no subscriptions left
    _subscriptions.clear();
}    

/**
 *  Cleanup the object
 *  We want to cleanup the job _before_ it is destructed, to handle the situation
 *  where user-space already destructs _core while the job is reporting its result
 *  @return Handler     the handler that may still be called
 */
Handler *RemoteLookup::cleanup()
{
    // remember the old handler
    auto handler = _handler;
    
    // forget the handler
    _handler = nullptr;
    
    // forget the tcp connection
    _connection.reset();
    
    // unsubscribe from all inbound sockets
    unsubscribe();

    if (handler) _core->done(shared_from_this());

    // expose the handler
    return handler;
}

/** 
 *  Time out the job because no appropriate response was received in time
 *  @return bool        should the lookup be resheduled?
 */
bool RemoteLookup::timeout()
{
    // before we report to userspace we cleanup the object
    cleanup()->onTimeout(this);
    
    // done (we do not have to run again)
    return false;
}

/**
 *  Execute the lookup
 *  @param  now         current time
 *  @return bool        should the lookup be rescheduled?
 */
bool RemoteLookup::execute(double now)
{
    // access to the nameservers + the number we have
    auto &nameservers = _core->nameservers();
    size_t nscount = nameservers.size();
    
    // which nameserver should we sent now?
    const Ip &nameserver = nameservers[_core->rotate() ? (_count + _id) % nscount : _count % nscount];

    // send a datagram to this server
    if (auto *inbound = _core->datagram(nameserver, _query))
    {
        // subscribe to the answers that might come in from now onwards
        inbound->subscribe(this, nameserver, _query.id());

        // store this subscription, so that we can unsubscribe on success
        _subscriptions.emplace(std::make_pair(inbound, nameserver));
    }

    // one more attempt has been made
    _count += 1; _last = now;

    // we want to be rescheduled
    return true;
}

/**
 *  Method to report the response
 *  This method checks if there is an NXDOMAIN error, if that is the case
 *  it is turned into an empty response if the /etc/hosts file holds a record for the host
 *  @param  response
 */
void RemoteLookup::report(const Response &response)
{
    // if the result has already been reported, we do nothing here
    if (_handler == nullptr) return;
    
    // for NXDOMAIN errors we need special treatment (maybe the hostname _does_ exists in 
    // /etc/hosts?) For all other type of results the message can be passed to userspace
    if (response.rcode() != ns_r_nxdomain) return cleanup()->onReceived(this, response);

    // extract the original question, to find out the host for which we were looking
    Question question(response);
    
    // there was a NXDOMAIN error, which we should not communicate if our /etc/hosts
    // file does have a record for this hostname, check this
    if (!_core->exists(question.name())) return cleanup()->onReceived(this, response);
    
    // get the original request (so that the response can match the request)
    Request request(this);
    
    // construct a fake-response message (it is fake because we have not actually received it)
    FakeResponse fake(request, question);

    // send the fake-response to user-space
    cleanup()->onReceived(this, Response(fake.data(), fake.size()));
}

/**
 *  Method that is called when a response is received
 *  @param  nameserver  the reporting nameserver
 *  @param  response    the received response
 *  @return bool        was the response processed?
 */
bool RemoteLookup::onReceived(const Ip &ip, const Response &response)
{
    // ignore responses that do not match with the query
    // @todo should we check for more? like whether the response is indeed a response
    if (!_query.matches(response)) return false;
    
    // if we're already busy with a tcp connection we ignore further dgram responses
    if (_connection) return false;
    
    // if the response was not truncated, we can report it to userspace
    if (!response.truncated()) { report(response); return true; }

    // switch to tcp mode to retry the query to get a non-truncated response
    _connection.reset(new Connection(_core->loop(), ip, _query, response, this));
    
    // we can unsubscribe from all inbound udp sockets because we're no longer interested in those responses
    unsubscribe();
    
    // remember the start-time of the connection to reset the timeout-period
    _last = Now();
    
    // done
    return true;
}

/**
 *  Called when the response has been received
 *  @param  connection
 *  @param  response
 */
void RemoteLookup::onReceived(Connection *connection, const Response &response)
{
    // if the operation was already cancelled
    if (_handler == nullptr) return;

    // ignore responses that do not match with the query
    // @todo should we check for more? like whether the response is indeed a response
    if (!_query.matches(response)) return;

    // we have a response, hand it over to user space
    report(response);
}

/**
 *  Called when the connection could not be used
 *  @param  connector   the reporting connection
 *  @param  response    the original answer (the original truncated one)
 */
void RemoteLookup::onFailure(Connection *connection, const Response &truncated)
{
    // if the operation was already cancelled
    if (_handler == nullptr) return;

    // we failed to get the regular response, so we send back the truncated response
    cleanup()->onReceived(this, truncated);
}

/**
 *  Cancel the operation
 */
void RemoteLookup::cancel()
{
    // do nothing if already cancelled
    if (_handler == nullptr) return;

    // cleanup, and remove to userspace
    cleanup()->onCancelled(this);
}

/**
 *  End of namespace
 */
}

