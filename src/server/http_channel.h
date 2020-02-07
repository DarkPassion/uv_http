//
// Created by zhifan zhang on 2020/2/3.
//

#ifndef UV_HTTP_HTTP_CHANNEL_H
#define UV_HTTP_HTTP_CHANNEL_H


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

class http_header;
class http_message;
class http_channel {

public:
    http_channel(uv_loop_t* loop);

    ~http_channel();

    int start_read();

    int stop_read();

    int write_buff(const char* buf, int len);

    int check_update();

    uv_tcp_t* get_client();

    int set_make_response_handler(int(*cb)(http_message*, http_channel*, void* user), void* user);

    friend class http_message;
private:
    int _input_parser_data(const char* data, size_t len);

    int _make_response(char* data, int len);
private:
    static void _static_uv_close_callback(uv_handle_t* handle);

    static void _static_uv_buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);

    static void _static_uv_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

    static void _static_uv_write_callback(uv_write_t* req, int status);

    static int _static_parser_header_data(http_parser *parser, const char *at, size_t length);

    static int _static_parser_set_resp_body(http_parser *parser, const char *at, size_t length);

    static int _static_parser_on_url(http_parser *parser, const char *at, size_t length);

    static int _static_parser_header_complete(http_parser *parser);

    static int _static_parser_message_complete(http_parser *parser);


    // typedef
    typedef int (*make_response_handler) (http_message* msg, http_channel* ch, void* user);

private:
    struct handler
    {
        make_response_handler make_response;
        void* make_response_user;
    };


    struct private_data
    {
        uv_loop_t*  _loop;
        uv_tcp_t*   _client;

        uint64_t    update_ts;

        http_parser*        _paser;
        http_parser_settings _settings;

        http_message*   _msg;

        uint8_t         _is_complete;
        char   _req_host[URL_MAX_LEN];
        char   _req_path[URL_MAX_LEN];


        uint16_t error_code;
        handler _handler;
    };

private:
    private_data    _pd;
};

NS_CC_END

#endif //UV_HTTP_HTTP_CHANNEL_H
