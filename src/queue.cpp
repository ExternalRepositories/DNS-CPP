#include "../include/dnscpp/queue.h"
#include "../include/dnscpp/lookup.h"

namespace DNS
{

void Queue::push(std::shared_ptr<Lookup> &item)
{
    _c.push_back(item);
    item->position(std::prev(_c.end()));
}

std::shared_ptr<Lookup> Queue::pop()
{
    auto item = std::move(_c.front());
    _c.pop_front();
    // item->clearPosition();
    return item;
}

/**
 *  @return whether this item was at the front of the queue
 */
bool Queue::pop(std::shared_ptr<Lookup> &item)
{
    const bool atFrontOfQueue = _c.begin() == item->position();
    _c.erase(item->position());
    // item->clearPosition();
    return atFrontOfQueue;
}

}
