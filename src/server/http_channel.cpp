//
// Created by zhifan zhang on 2020/2/3.
//

#include <string.h>
#include "server/http_channel.h"
#include "server/http_message.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "data/send_data.h"
#include "data/http_code.h"
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

    _pd._msg = new http_message();
    _pd._sed_q = new send_queue();

    memset(_pd._req_path, 0, ARRAY_SIZE(_pd._req_path));
    memset(_pd._req_host, 0, ARRAY_SIZE(_pd._req_host));


}

http_channel::~http_channel()
{
    if (_pd._client && uv_is_active((uv_handle_t*) _pd._client)) {
        uv_close((uv_handle_t*) _pd._client, _static_uv_close_callback);
        log_d("http_channel dctor close socket");
    }

    if (_pd._msg) {
        delete _pd._msg;
        _pd._msg = NULL;
    }

    if (_pd._sed_q) {
        delete _pd._sed_q;
        _pd._sed_q = NULL;
    }

    if (_pd._paser) {
        free(_pd._paser);
        _pd._paser = NULL;
    }

    log_d("http_channel dctor");
}

uv_tcp_t* http_channel::get_client()
{
    return _pd._client;
}

int http_channel::set_make_response_handler(int (*cb)(http_message *, http_channel *, void *), void *user)
{
    log_d("set_make_response_handler, cb:%p", cb);
    _pd._handler.make_response = cb;
    _pd._handler.make_response_user = user;
    return 0;
}

int http_channel::set_malloc_handler(void (*cb)(uint8_t **, uint32_t &, void *), void *user)
{
    log_d("set_malloc_handler, cb:%p", cb);
    _pd._handler._malloc = cb;
    _pd._handler._malloc_user = user;
    return 0;
}

int http_channel::set_free_handler(void (*cb)(uint8_t *, uint32_t, void *), void *user)
{
    log_d("set_free_handler, cb:%p", user);
    _pd._handler._free = cb;
    _pd._handler._free_user = user;
    return 0;
}

int http_channel::start_read()
{
    int ret = uv_read_start((uv_stream_t*)_pd._client, _static_uv_buffer_alloc, _static_uv_read_callback);
    if (ret != 0) {
        log_d("uv_read_start fail");
        return -1;
    }
    _pd.update_ts = utils::get_timestamp();
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

int http_channel::write_buff(send_data* data, uint8_t end)
{
    if (!uv_is_active((uv_handle_t*) _pd._client)) {
        log_d("write_buff, uv_is_active false");
        return -1;
    }

    _pd._is_write_end = end;


    int ret = uv_write(&data->write, (uv_stream_t*) _pd._client, data->buf, data->nbuf, _static_uv_write_callback);
    log_d("_input_parser_data, uv_write ret:%d", ret);
    return 0;
}



int http_channel::check_update()
{
    uint64_t cts = utils::get_timestamp();
    if (cts > _pd.update_ts + SOCKET_TIMEOUT_MS || _pd._client == NULL || !uv_is_active((uv_handle_t*) _pd._client)) {
        return -1;
    }
    log_d("http_channel::do_update(), cts:%llu", cts);
    return 0;
}

int http_channel::_input_parser_data(const char *data, size_t len)
{
    int np = http_parser_execute(_pd._paser, &_pd._settings, data, len);
    if (np != len) {
        log_d("http_parser_execute fail");
        return -1;
    }

    if (_pd._handler.make_response == NULL) {
        log_d("_handler.make_response = null");
        return -1;
    }

    if (_pd._is_complete > 0) {
        std::string url;
        url.append("http://");
        url.append(_pd._req_host);
        url.append(_pd._req_path);
        log_d("make_response, url:%s", url.c_str());
        _pd._msg->get_url()->reset_url(url.c_str());
        int ret = _pd._handler.make_response(_pd._msg, this, _pd._handler.make_response_user);
        log_d("_handler.make_response, ret:%d", ret);
    }
    return 0;
}

int http_channel::_make_response(char *data, int len)
{
#if 1
    const char* TPL = "HTTP/1.1 200 OK\r\n"
                      "Server: uv_http_server\r\n"
                      "Content-Type: text/html;charset=UTF-8\r\n"
                      "Date: Fri, 07 Feb 2020 02:36:02 GMT\r\n"
                      "Cache-Control: no-cache\r\n"
                      "Connection: close\r\n"
                      "Content-Length: 5\r\n"
                      "\r\n"
                      "hello";

    int ns = snprintf(data, len, "%s", TPL);
    log_d("_make_response, ns:%d data:%s", ns, data);
    return ns;
#endif

#if 0
    // [chunk size] [\r\n] [chunk data] [\r\n] [chunk size] [\r\n] [chunk data] [\r\n] [chunk size = 0] [\r\n] [\r\n]
    const char* CHUNK_TPL = "HTTP/1.1 200 OK\r\n"
                      "Server: uv_http_server\r\n"
                      "Content-Type: text/html;charset=UTF-8\r\n"
                      "Date: Fri, 07 Feb 2020 02:36:02 GMT\r\n"
                      "Cache-Control: no-cache\r\n"
                      "Connection: close\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "\r\n";

    char chunk[1024] = {0};
    int pos = 0;

    int s = 12;
    int ns = 0;
    char str[128] = {0};
    for (int i = 0; i < s; i++) {
        str[i] = i;
    }

    // write size
    ns = snprintf(chunk + pos, ARRAY_SIZE(chunk) - pos, "%x\r\n", s);
    pos += ns;

    // cp data
    memcpy(chunk + pos, str, s);
    pos += s;

    // write '\r\n'
    ns = snprintf(chunk + pos, ARRAY_SIZE(chunk) - pos, "\r\n");
    pos += ns;

    // write size
    ns = snprintf(chunk + pos, ARRAY_SIZE(chunk) - pos, "%x\r\n", s);
    pos += ns;

    // cp data
    memcpy(chunk + pos, str, s);
    pos += s;

    // write '\r\n'
    ns = snprintf(chunk + pos, ARRAY_SIZE(chunk) - pos, "\r\n");
    pos += ns;


    ns = snprintf(chunk + pos, ARRAY_SIZE(chunk) - pos, "%x\r\n\r\n", 0);
    pos += ns;



    ns = snprintf(data, len, "%s", CHUNK_TPL);

    if (ns + pos < len) {
        memcpy(data + ns, chunk, pos);
    }
    log_d("_make_response, ns:%d data:%s", ns, data);
    return ns + pos;
#endif
}

// uv callback
void http_channel::_static_uv_close_callback(uv_handle_t* handle)
{
    http_channel* pthis = (http_channel*) handle->data;
    if (pthis->_pd._client == (uv_tcp_t*) handle) {
        log_d("_static_uv_close_callback, handle:%p", handle);
        free(handle);
        pthis->_pd._client = NULL;
    }
}

void http_channel::_static_uv_buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    log_d("buffer_alloc size:%zu", size);
    buf->base = (char*) malloc(size);
    buf->len = size;
}

void http_channel::_static_uv_write_callback(uv_write_t *req, int status)
{
    log_d("_static_uv_write_callback, status:%d", status);
    send_data* __send = (send_data*) req->data;
    http_channel* pthis = (http_channel*) __send->data;

    pthis->_pd._sed_q->delete_data(__send);

    if (status == UV_ECANCELED) {
        log_t("_static_uv_write_callback has been close");
        pthis->_pd.error_code = ERROR_SOCKET_WRITE;
        return;
    }

    if (status < 0) {
        log_t("_static_uv_write_callback error");
        pthis->_pd.error_code = ERROR_SOCKET_WRITE;
        return;
    }

    pthis->_pd.update_ts = utils::get_timestamp();

    if (pthis->_pd._is_write_end) {
        // close socket
        uv_close((uv_handle_t*) pthis->_pd._client, _static_uv_close_callback);
        log_d("_static_uv_write_callback, close socket");
    }
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

    pthis->_pd.update_ts = utils::get_timestamp();
#undef FREE_BUF
}

// http parser callback
int http_channel::_static_parser_header_data(http_parser *parser, const char *at, size_t length)
{
    http_channel* pthis = (http_channel*) parser->data;

    pthis->_pd._msg->get_request_http_header()->append_data(at, length);
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
    std::string host = pthis->_pd._msg->get_request_http_header()->get_value_by_key("Host");
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