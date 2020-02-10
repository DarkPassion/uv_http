//
// Created by zhifan zhang on 2020/2/3.
//

#ifndef UV_HTTP_HTTP_SERVER_H
#define UV_HTTP_HTTP_SERVER_H

#include <vector>
#include "util/define.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "uv.h"
#include "http_parser.h"

#ifdef __cplusplus
}
#endif


NS_CC_BEGIN

class http_channel;
class http_message;
class http_route;
class buffer_cache;
class http_server {

public:
    http_server();

    ~http_server();

    int start_server(const char* ip, uint16_t port);

    int add_handler(const char* path, int(*cb) (http_message* msg, http_channel* channel, void* user), void* user);

private:
    int _init_private_data();

    int _deinit_private_data();

    int _init_uv_data();

    int _deinit_uv_data();

private:
    static void _static_malloc_handler(uint8_t** data, uint32_t& len, void* user);

    static void _static_free_handler(uint8_t* data, uint32_t len, void* user);

    static void __uv_thread_entry_static(void* data);

    static void _static_uv_connection_callback(uv_stream_t* server, int status);

    static void _static_uv_timer_callback(uv_timer_t* handle);
private:

    enum {
        THERAD_IDEL = 0,
        THREAD_PREPARE,
        THREAD_RUN,
        THREAD_END,
    };
    struct private_data {
        uv_loop_t* _loop;
        uv_tcp_t* _server;
        uv_timer_t* _timer;

        uv_thread_t _thread;
        struct sockaddr_in _saddr;

        char bind_ip[64];
        uint16_t bind_port;
        uint8_t is_run;
    };

    typedef std::vector<http_channel*> channel_queue;
private:
    private_data    _pd;
    channel_queue   _channels;
    http_route*      _route;
    buffer_cache*   _buffer;
};

NS_CC_END

#endif //UV_HTTP_HTTP_SERVER_H
