#pragma once

#include <list>
#include <memory>

namespace DNS {

class Lookup;

class Queue final
{
    using Container = std::list<std::shared_ptr<Lookup>>;
    Container _c;

public:

    using Iterator = typename Container::iterator;
    using ConstIterator = typename Container::const_iterator;

    void push(std::shared_ptr<Lookup> &item);

    size_t size() const noexcept { return _c.size(); }

    bool empty() const noexcept { return _c.empty(); }

    std::shared_ptr<Lookup> &front() noexcept { return _c.front(); }

    std::shared_ptr<Lookup> pop();

    /**
     *  @return whether this item was at the front of the queue
     */
    bool pop(std::shared_ptr<Lookup> &item);
};

}
