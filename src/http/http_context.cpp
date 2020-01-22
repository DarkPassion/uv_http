//
// Created by zhifan zhang on 2020/1/22.
//

#include "http_context.h"
#include "util/logger.h"
#include <stdlib.h>

NS_CC_BEGIN



http_context::http_context()
{
    _pd = new private_data();
    memset(_pd, 0, sizeof(private_data));
}

http_context::~http_context()
{
    if (_pd) {
        _deinit_private_data();
        delete _pd;
    }
}



// private functions
int http_context::_init_private_data()
{

    _pd->_loop = (uv_loop_t*) malloc(sizeof(uv_loop_s));
    uv_loop_init(_pd->_loop);
    _pd->_loop->data = this;

    _pd->_conn = (uv_stream_s*) malloc(sizeof(uv_stream_s));
    memset(_pd->_conn, 0, sizeof(uv_stream_s));
    _pd->_conn->data = this;

    _pd->_timer = (uv_timer_t*) malloc(sizeof(uv_timer_t));
    memset(_pd->_timer, 0, sizeof(uv_timer_t));
    _pd->_timer->data = this;

    _pd->_addr = (uv_getaddrinfo_t*) malloc(sizeof(uv_getaddrinfo_t));
    memset(_pd->_addr, 0, sizeof(uv_getaddrinfo_t));
    _pd->_addr->data = this;

    _pd->_paser = (http_parser*) malloc(sizeof(http_parser));
    memset(_pd->_paser, 0, sizeof(http_parser));
    _pd->_paser->data = this;


    memset(&_pd->_settings, 0, sizeof(http_parser_settings));
    _pd->_settings.on_status = &http_context::_static_parser_set_status_code;
    _pd->_settings.on_body = &http_context::_static_parser_set_resp_body;
    _pd->_settings.on_header_field = &http_context::_static_parser_header_data;

    return 0;
}

int http_context::_deinit_private_data()
{
    if (_pd == NULL) {
        log_d("_pd = NULL ");
        return 0;
    }


    return 0;
}


// http_parser callback
int http_context::_static_parser_set_status_code(http_parser *parser, const char *at, size_t length)
{
    http_context* pthis = (http_context*) parser->data;
    if (pthis->_pd && pthis->_pd->_paser != parser) {
        log_n("_static_parser_set_status_code paser neq");
        return 0;
    }

    pthis->_pd->status_code =  (uint16_t) std::strtol(at - 4, NULL, 10);
    log_t("status_code:%d", pthis->_pd->status_code);
    return 0;
}


int http_context::_static_parser_header_data(http_parser *parser, const char *at, size_t length)
{
    return 0;
}

int http_context::_static_parser_set_resp_body(http_parser *parser, const char *at, size_t length)
{
    return 0;
}

NS_CC_END
