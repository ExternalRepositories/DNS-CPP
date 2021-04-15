/**
 *  Lookup.h
 * 
 *  This is the base class for all lookup implementations. It is only
 *  used internally, user space code does not interact with it.
 * 
 *  @author Emiel Bruijntjes <emiel.bruijntjes@copernica.com>
 *  @copyright 2021 Copernica BV
 */

/**
 *  Include guard
 */
#pragma once

/**
 *  Dependencies
 */
#include "operation.h"
#include "queue.h"

/**
 *  Begin of namespace
 */
namespace DNS {

/**
 *  Forward declarations
 */
//class Handler;

/**
 *  Class definition
 */
class Lookup : public Operation
{
private:
    Queue::ConstIterator _position;

protected:
    /**
     *  Constructor
     *  @param  handler     user space handler
     *  @param  op          the type of operation (normally a regular query)
     *  @param  dname       the domain to lookup
     *  @param  type        record type to look up
     *  @param  bits        extra bits to be included in the query
     *  @param  data        optional data (only for type = ns_o_notify)
     *  @throws std::runtime_error
     */
    Lookup(Handler *handler, int op, const char *dname, int type, const Bits &bits, const unsigned char *data = nullptr) :
        Operation(handler, op, dname, type, bits, data) {}

public:
    /**
     *  Destructor
     */
    virtual ~Lookup() = default;
    
    /**
     *  How many credits are left (meaning: how many datagrams do we still have to send?)
     *  @return size_t      number of attempts
     */
    virtual size_t credits() const = 0;

    /**
     *  Get the time at which this lookup was executed
     *  @return double
     */
    virtual double timestamp() const noexcept = 0;

    /**
     *  Execute the lookup
     *  @param  now         current time
     *  @return True when the execution succeeded, false if not
     */
    virtual bool execute(double now) = 0;

    Queue::ConstIterator position() const noexcept { return _position; }
    void position(Queue::ConstIterator value) { _position = value; }
};
    
/**
 *  End of namespace
 */
}
