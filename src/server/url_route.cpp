//
// Created by zhifan zhang on 2020/2/3.
//

#include "server/url_route.h"
#include "util/logger.h"

NS_CC_BEGIN


url_route::url_route()
{
    _queue.clear();
}


url_route::~url_route()
{
    _queue.clear();
}


int url_route::add_handler(const char *path, int (*cb)(http_message *, http_channel *, void *), void *user)
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


int url_route::remove_handle(const char *path)
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


int url_route::do_route(const char *path, http_message *msg, http_channel *channel)
{
    return 0;
}

NS_CC_END
