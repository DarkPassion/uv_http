//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_HTTP_CONTEXT_H
#define UV_HTTP_HTTP_CONTEXT_H

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

class http_context {

public:
    http_context();

    ~http_context();

private:
    struct private_data
    {
        uv_loop_t* _loop;
        uv_stream_t* _conn;
        uv_getaddrinfo_t* _addr;
        uv_timer_t* _timer;
        http_parser* _paser;
        http_parser_settings _settings;

        int status_code;
    };

    int _init_private_data();

    int _deinit_private_data();

private:
    // uv_alloc

    // http_parser
    static int _static_parser_set_status_code(http_parser * parser, const char * at, size_t length);
    static int _static_parser_set_resp_body(http_parser * parser, const char * at, size_t length);
    static int _static_parser_header_data(http_parser * parser, const char * at, size_t length);
private:
    private_data* _pd;

};

NS_CC_END

#endif //UV_HTTP_HTTP_CONTEXT_H
