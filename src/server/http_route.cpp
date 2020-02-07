//
// Created by zhifan zhang on 2020/2/3.
//

#include "server/http_route.h"
#include "server/http_message.h"
#include "server/http_channel.h"
#include "http/http_url.h"

#include "util/logger.h"

NS_CC_BEGIN


http_route::http_route()
{
    _queue.clear();
}


http_route::~http_route()
{
    _queue.clear();
}


int http_route::add_handler(const char *path, int (*cb)(http_message *, http_channel *, void *), void *user)
{
    if (path == NULL || cb == NULL) {
        log_d("add_handler, path = null, cb = null, fail");
        return -1;
    }

    uint8_t is_add = 0;
    std::vector<route_data*>::iterator it = _queue.begin();
    for ( ; it != _queue.end(); it++) {
        route_data* data = *it;
        if (data && strcmp(path, data->path) == 0) {
            data->func = cb;
            data->user = user;
            is_add = 1;
            log_d("add_handler old, cb:%p, path:%s", cb, path);
            break;
        }
    }

    if (is_add == 0) {
        route_data* data = new route_data;
        memset(data, 0, sizeof(route_data));
        snprintf(data->path, ARRAY_SIZE(data->path), "%s", path);
        data->func = cb;
        data->user = user;
        is_add = 1;

        log_d("add_handler new, cb:%p, path:%s", cb, path);
    }

    return 0;
}


int http_route::remove_handle(const char *path)
{
    if (path == NULL) {
        log_d("remove_handle, path = null");
        return -1;
    }

    uint8_t is_remove = 0;
    std::vector<route_data*>::iterator it = _queue.begin();
    for ( ; it != _queue.end(); it++) {
        route_data* data = *it;
        if (data && strcmp(data->path, path) == 0) {
            delete data;
            _queue.erase(it);
            is_remove = 1;
            break;
        }
    }

    log_d("remove_handle, %hhu", is_remove);
    return 0;
}


int http_route::do_route(const char *path, http_message *msg, http_channel *channel)
{
    return 0;
}


int http_route::__static_route_index(uv_http::http_message* msg, uv_http::http_channel* ch, void* user)
{
    http_route* pthis = (http_route*) user;


    if (msg == NULL || ch == NULL) {
        log_d("__static_route_index param input error");
        return -1;
    }

    if (pthis->_queue.size() == 0) {
        msg->make_simple_response(ch, 200, "hello", 5);
        return 0;
    }

    std::string path = msg->get_url()->get_path();
    return pthis->do_route(path.c_str(), msg, ch);
}


NS_CC_END
