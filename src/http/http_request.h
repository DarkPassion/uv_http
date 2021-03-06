//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_HTTP_REQUEST_H
#define UV_HTTP_HTTP_REQUEST_H

#include <string>
#include <vector>

#include "util/define.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"


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
class http_chunk;
class buffer_cache;
class http_request {
public:
    struct http_result;

    http_request(const char* url, std::string* header = NULL, std::string* body = NULL, int method = HTTP_GET);

    ~http_request();

    int set_keep_alive(int on);

    int set_follow_location(int on);

    int do_work();

    int stop_work();

    int get_result(http_result* result);

    int set_write_callback(void(*cb)(const char* buf, size_t len, void* data), void* user);

    int set_response_callback(void(*cb)(int error, http_request* request, void* data), void* user);

    int set_notify_callback(void(*cb)(int type, const char* buf, size_t len, void* data), void* user);


    enum notify_code {
        NOTIFY_CONNECT_IP = 1,
        NOTIFY_STATUS_CODE,
    };

    struct http_result
    {
        int status_code;
        char connect_ip[64];
        uint16_t error_code;
        std::string content;
    };

private:
    struct ssl_trans
    {
        SSL_CTX*    ctx;
        SSL*        ssl;
        BIO*        read_bio;
        BIO*        write_bio;
        buffer_cache*   wb;
        uint8_t     send_req;
    };


    struct private_data
    {
        uv_loop_t* _loop;
        uv_tcp_t* _conn;
        uv_getaddrinfo_t* _addr;
        uv_timer_t* _timer;
        http_parser* _paser;
        http_parser_settings _settings;

        struct sockaddr_in _saddr;
        std::string* _req_body;
        std::string* _req_header;
        std::string* _req_buffer;
        http_url* _req_url;

        ssl_trans*  _trans;
        http_chunk* _chunk;
        http_header* _res_header;
        std::string* res_body;

        int http_method;
        int status_code;

        uint8_t keep_alive;
        uint8_t follow_location;
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

    int _try_follow_location();

    int _input_http_parser_data(const char* data, int len);

    int _init_ssl_trans();

    int _deinit_ssl_trans();

    int _ssl_trans_cycle();

    int _ssl_trans_handle_error(int result);

    int _ssl_trans_flush_read_bio();

    int _ssl_trans_check_write_data();

    int _ssl_trans_handle_disconnect();

private:
    typedef void(* response_cb) (int error, http_request* request, void* data);
    typedef void(* write_cb) (const char* buf, size_t len, void* data);
    typedef void(* notify_cb) (int type, const char* buf, size_t len, void* data);

    struct callback_t
    {
        response_cb rcb;
        void* rcb_data;

        write_cb  wcb;
        void* wcb_data;

        notify_cb ncb;
        void* ncb_data;
    };
private:
    // uv callback
    static void buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);

    static void _static_uv_close_cb(uv_handle_t* handle);

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
    private_data    _pd;
    callback_t      _callback;
};

NS_CC_END

#endif //UV_HTTP_HTTP_REQUEST_H
