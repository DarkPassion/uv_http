//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_HTTP_REQUEST_H
#define UV_HTTP_HTTP_REQUEST_H

#include <string>

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

class http_url;
class http_header;

class http_request {

public:
    http_request(const char* url, std::string* header = NULL, std::string* body = NULL, int method = HTTP_GET);

    ~http_request();

    int do_work();

    int stop_work();

    enum {
        ERROR_SUCC = 0,
        ERROR_DNS_RESOLVE = 1,
        ERROR_CONNECT = 2,
        ERROR_SOCKET_READ = 3,
        ERROR_SOCKET_WRITE = 4,
        ERROR_TIMEOUT = 5,
        ERROR_INTERNAL = 6,
    };
private:
    struct private_data
    {
        uv_loop_t* _loop;
        uv_tcp_t* _conn;
        uv_getaddrinfo_t* _addr;
        uv_timer_t* _timer;
        uv_write_t* _conn_write;
        http_parser* _paser;
        http_parser_settings _settings;

        struct sockaddr_in _saddr;
        std::string* _req_body;
        std::string* _req_header;
        std::string* _req_buffer;
        http_url* _req_url;

        http_header* _res_header;
        std::string* res_buffer;

        int http_method;
        int status_code;

        uint8_t stop_flags;
        uint16_t error_code;
    };

    int _init_private_data();

    int _deinit_private_data();

    int _init_uv();

    int _deinit_uv();

    int _make_request();

    int _write_request();

    int _connect_to_server(const char* host, int16_t port);


private:
    // uv callback
    static void buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);

    static void _static_uv_walk_cb(uv_handle_t* handle, void* arg);

    static void _static_uv_connect_cb(uv_connect_t *req, int status);

    static void _static_uv_socket_timer_cb(uv_timer_t *handle);

    static void _static_uv_write_cb(uv_write_t* req, int status);

    static void _static_uv_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

    static void _static_uv_get_addrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

    // http_parser
    static int _static_parser_set_status_code(http_parser * parser, const char * at, size_t length);
    static int _static_parser_set_resp_body(http_parser * parser, const char * at, size_t length);
    static int _static_parser_header_data(http_parser * parser, const char * at, size_t length);
private:
    private_data* _pd;

};

NS_CC_END

#endif //UV_HTTP_HTTP_REQUEST_H
