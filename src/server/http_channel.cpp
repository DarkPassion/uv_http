//
// Created by zhifan zhang on 2020/2/3.
//

#include <string.h>
#include "server/http_channel.h"
#include "http/http_header.h"
#include "util/utils.h"
#include "util/logger.h"


NS_CC_BEGIN


http_channel::http_channel(uv_loop_t* loop)
{
    memset(&_pd, 0, sizeof(private_data));
    _pd._loop = loop;
    _pd._client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    memset(_pd._client, 0, sizeof(uv_tcp_t));
    _pd._client->data = this;
    int ret = uv_tcp_init(loop, _pd._client);
    if (ret != 0) {
        log_t("uv_tcp_init fail");
    }

    _pd._paser = (http_parser*) malloc(sizeof(http_parser));
    http_parser_init(_pd._paser, HTTP_REQUEST);
    _pd._paser->data = this;

    memset(&_pd._settings, 0, sizeof(http_parser_settings));
    _pd._settings.on_header_value = &http_channel::_static_parser_header_data;
    _pd._settings.on_header_field = &http_channel::_static_parser_header_data;
    _pd._settings.on_body = &http_channel::_static_parser_set_resp_body;
    _pd._settings.on_url = &http_channel::_static_parser_on_url;
    _pd._settings.on_headers_complete = &http_channel::_static_parser_header_complete;
    _pd._settings.on_message_complete = &http_channel::_static_parser_message_complete;

    _pd._req_header = new http_header();
    memset(_pd._req_path, 0, ARRAY_SIZE(_pd._req_path));
    memset(_pd._req_host, 0, ARRAY_SIZE(_pd._req_host));


}

http_channel::~http_channel()
{
    if (uv_is_active((uv_handle_t*) _pd._client)) {
        uv_close((uv_handle_t*) _pd._client, _static_uv_close_callback);
    }


    log_d("http_channel dctor");
}

uv_tcp_t* http_channel::get_client()
{
    return _pd._client;
}

int http_channel::start_read()
{
    int ret = uv_read_start((uv_stream_t*)_pd._client, _static_uv_buffer_alloc, _static_uv_read_callback);
    if (ret != 0) {
        log_d("uv_read_start fail");
        return -1;
    }
    return 0;
}

int http_channel::stop_read()
{
    log_d("stop_read");
    if (uv_is_active((uv_handle_t*) _pd._client)) {
        int ret = uv_read_stop((uv_stream_t*) _pd._client);
        if (ret != 0) {
            log_d("uv_read_stop fail");
            return -1;
        }
    }
    return 0;
}

int http_channel::do_update()
{
    uint64_t cts = utils::get_timestamp();
    return 0;
}

int http_channel::_input_parser_data(const char *data, size_t len)
{
    int np = http_parser_execute(_pd._paser, &_pd._settings, data, len);
    if (np != len) {
        log_d("http_parser_execute fail");
        return -1;
    }


    if (_pd._is_complete > 0) {
        // FIXME: close socket ??
        log_d("_input_parser_data close socket");
        stop_read();
    }
    return 0;
}

// uv callback
void http_channel::_static_uv_close_callback(uv_handle_t* handle)
{
    free(handle);
}

void http_channel::_static_uv_buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    log_d("buffer_alloc size:%zu", size);
    buf->base = (char*) malloc(size);
    buf->len = size;
}

void http_channel::_static_uv_read_callback(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    log_d("_static_uv_read_callback, nread:%d", nread);
#define FREE_BUF(b) if (b->base && b->len > 0) { free(b->base); }

    http_channel* pthis = (http_channel*) stream->data;

    if (nread < 0) {
        log_n("_static_uv_read_callback nread < 0");

        if (nread == UV_EOF) {
            log_n("_static_uv_read_callback eof");
        }
        FREE_BUF(buf);
        return;
    }

    int ret = pthis->_input_parser_data(buf->base, nread);
    if (ret != 0) {
        log_d("_input_parser_data fail");
    }
    FREE_BUF(buf);

#undef FREE_BUF
}

// http parser callback
int http_channel::_static_parser_header_data(http_parser *parser, const char *at, size_t length)
{
    http_channel* pthis = (http_channel*) parser->data;

    pthis->_pd._req_header->append_data(at, length);
    return 0;
}

int http_channel::_static_parser_set_resp_body(http_parser *parser, const char *at, size_t length)
{
    log_d("_static_parser_set_resp_body, ");
    return 0;
}

int http_channel::_static_parser_on_url(http_parser *parser, const char *at, size_t length)
{
    http_channel* pthis = (http_channel*) parser->data;

    int nc = length > ARRAY_SIZE(pthis->_pd._req_path) ? ARRAY_SIZE(pthis->_pd._req_path) : length;
    memcpy(pthis->_pd._req_path, at, nc);

    log_d("_static_parser_on_url, path:%s", pthis->_pd._req_path);

    return 0;
}

int http_channel::_static_parser_header_complete(http_parser *parser)
{
    log_d("_static_parser_header_complete ");
    http_channel* pthis = (http_channel*) parser->data;

    // get host
    std::string host = pthis->_pd._req_header->header_value_by_key("Host");
    if (host.size() > 0) {
        snprintf(pthis->_pd._req_host, ARRAY_SIZE(pthis->_pd._req_host), "%s", host.c_str());
        log_d("_static_parser_header_complete, host:%s", pthis->_pd._req_host);
    }

    return 0;
}


int http_channel::_static_parser_message_complete(http_parser *parser)
{
    http_channel* pthis = (http_channel*) parser->data;

    pthis->_pd._is_complete = 1;
    log_d("_static_parser_message_complete");

    return 0;
}


NS_CC_END