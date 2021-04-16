/**
 *  Core.cpp
 * 
 *  Implementation file for the Core class
 * 
 *  @author Emiel Bruijntjes <emiel.bruijntjes@copernica.com>
 *  @copyright 2020 - 2021 Copernica BV
 */

/**
 *  Dependencies
 */
#include "../include/dnscpp/core.h"
#include "../include/dnscpp/lookup.h"
#include "../include/dnscpp/loop.h"
#include "../include/dnscpp/watcher.h"
#include <cassert>

/**
 *  Begin of namespace
 */
namespace DNS {

/**
 *  Constructor
 *  @param  loop        your event loop
 *  @param  defaults    should defaults from resolv.conf and /etc/hosts be loaded?
 *  @param  buffersize  send & receive buffer size of each UDP socket
 *  @throws std::runtime_error
 */
Core::Core(Loop *loop, bool defaults) :
    _loop(loop),
    _ipv4(loop, this),
    _ipv6(loop, this)
{
    // do nothing if we don't need the defaults
    if (!defaults) return;
    
    // load the defaults from /etc/resolv.conf
    ResolvConf settings;
    
    // copy the nameservers
    for (size_t i = 0; i < settings.nameservers(); ++i) _nameservers.emplace_back(settings.nameserver(i));
    
    // take over some of the settings
    _timeout = settings.timeout();
    _interval = settings.timeout();
    _attempts = settings.attempts();
    _rotate = settings.rotate();

    // we also have to load /etc/hosts
    if (!_hosts.load()) throw std::runtime_error("failed to load /etc/hosts");
}

/**
 *  Protected constructor, only the derived class may construct it
 *  @param  loop        your event loop
 *  @param  settings    settings from the resolv.conf file
 *  @param  buffersize  send & receive buffer size of each UDP socket
 */
Core::Core(Loop *loop, const ResolvConf &settings) :
    _loop(loop),
    _ipv4(loop, this),
    _ipv6(loop, this)
{
    // construct the nameservers
    for (size_t i = 0; i < settings.nameservers(); ++i) _nameservers.emplace_back(settings.nameserver(i));

    // take over some of the settings
    _timeout = settings.timeout();
    _interval = settings.timeout();
    _attempts = settings.attempts();
    _rotate = settings.rotate();
}


/**
 *  Destructor
 */
Core::~Core()
{
    // stop timer (in case it is still running)
    if (_timer == nullptr) return;
    
    // stop the timer
    _loop->cancel(_timer, this);
}

/**
 *  Add a new lookup to the list
 *  @param  lookup
 *  @return Operation
 */
Operation *Core::add(std::shared_ptr<Lookup> lookup)
{
    return reschedule(std::shared_ptr<Lookup>(lookup));
}

Operation *Core::reschedule(std::shared_ptr<Lookup> lookup)
{
    _scheduled.push(lookup);
    onBuffered(nullptr);
    return lookup.get();
}

/**
 *  Method that is called when a UDP socket has a buffer that it wants to deliver
 *  @param  udp         the socket with a buffer
 */
void Core::onBuffered(Udps *udp)
{
    // if the timer is already running we have to reset it
    if (_timer != nullptr) _loop->cancel(_timer, this);

    // check when the next operation should run
    _timer = _loop->timer(0.0, this);
}

/**
 *  Method that is called when the timer expires
 */
void Core::expire()
{
    // forget the timer
    _loop->cancel(_timer, this); _timer = nullptr;
    
    // a call to userspace might destruct `this`
    Watcher watcher(this);
    
    // get the current time
    Now now;

    // Step 1: process buffered raw responses.
    // This removes lookups from _lookups, most likely not at the front of the queue.
    // This is the sole reason why we need to keep an iterator so that removals are O(1).
    size_t maxcalls = 8;
    maxcalls -= _ipv4.deliver(maxcalls); if (!watcher.valid()) return;
    maxcalls -= _ipv6.deliver(maxcalls); if (!watcher.valid()) return;

    // Step 2: invoke callback handlers of all ready lookups (but not too many)
    for (size_t i = 0, end = std::min(maxcalls, _ready.size()); i != end; ++i) _ready.pop();

    // Step 3: execute awaiting lookups
    while (_lookups.size() < _capacity && !_scheduled.empty())
    {
        auto lookup = _scheduled.pop();
        if (lookup->execute(now)) _lookups.push(lookup);
        else if (lookup->credits()) _scheduled.push(lookup);
        else _ready.push(lookup);
    }

    // Step 4: pop off the timed-out lookups, and
    // - if the lookup has credits left (retries), stick it into the scheduled queue again
    // - otherwise there are no more attempts left, we put it into the ready queue
    const double timeouttime = now - _timeout;
    while (!_lookups.empty() && _lookups.front()->timestamp() <= timeouttime)
    {
        auto lookup = _lookups.pop();
        if (lookup->credits()) _scheduled.push(lookup);
        else _ready.push(lookup);
    }

    // Step 5: schedule the timer to fire at an appropriate time.
    // There might be ready lookups ready to have their callback handlers invoked still,
    // since we only process a fixed amount of them per timer expiry. In that case,
    // let's expire as soon as possible again.
    if (!_ready.empty())
    {
        _timer = _loop->timer(0.0, this);
    }
    // Or it may have added inflight lookups.
    // set the timer to expire at the time when the front-most lookup expires.
    else if (!_lookups.empty())
    {
        const double earliest = _lookups.front()->timestamp() + _timeout - now;
        _timer = _loop->timer(std::max(0.0, earliest), this);
    }
    else
    {
        // At this point, both _ready and _lookups were empty.
        // So the _scheduled queue must also be empty.
        assert(_scheduled.empty());
    }
}

/**
 *  Send a message over a UDP socket
 *  @param  ip              target IP
 *  @param  query           the query to send
 *  @return Inbound         the object that receives the answer
 */
Inbound *Core::datagram(const Ip &ip, const Query &query)
{
    // check the version number of ip
    switch (ip.version()) {
    case 4:     return _ipv4.send(ip, query);
    case 6:     return _ipv6.send(ip, query);
    default:    return nullptr;
    }
}

void Core::done(std::shared_ptr<Lookup> lookup)
{
    bool front = _lookups.pop(lookup);
    _ready.push(lookup);
    if (!front) return;
    // need to reschedule the timer so that it times out earlier
    // @todo or may just let it expire
}

/**
 *  End of namespace
 */
}

