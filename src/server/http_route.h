//
// Created by zhifan zhang on 2020/2/3.
//

#ifndef UV_HTTP_HTTP_ROUTE_H
#define UV_HTTP_HTTP_ROUTE_H

#include <vector>

#include "util/define.h"

NS_CC_BEGIN

class http_message;
class http_channel;
class http_server;

class http_route {
public:
    http_route();

    ~http_route();

    int add_handler(const char* path, int(*cb)(http_message* msg, http_channel* channel, void* user), void* user);

    int remove_handle(const char* path);

    int do_route(const char* path, http_message* msg, http_channel* channel);

    friend class http_server;
private:
    static int __static_route_index(http_message*, http_channel*, void* user);

private:
    typedef int(* handle_func) (http_message* msg, http_channel* channel, void* user);

    struct route_data
    {
        char path[URL_MAX_LEN];
        handle_func func;
        void* user;
    };

    std::vector<route_data*> _queue;
};


NS_CC_END

#endif //UV_HTTP_HTTP_ROUTE_H
