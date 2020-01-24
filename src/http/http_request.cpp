//
// Created by zhifan zhang on 2020/1/22.
//

#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <sstream>
#include <algorithm>
#include <functional>

#include "http/http_request.h"
#include "http/http_url.h"
#include "http/http_header.h"
#include "util/logger.h"

NS_CC_BEGIN

static const char* Location = "Location";


http_request::http_request(const char* url, std::string* header, std::string* body, int method)
{
    _pd = new private_data();
    memset(_pd, 0, sizeof(private_data));

    int ret = _init_private_data();
    log_d("init_private_data, ret = %d", ret);

    _pd->_req_header = header;
    _pd->_req_body = body;
    _pd->http_method = method;

    ret = _pd->_req_url->reset_url(url);
    if (ret != 0) {
        log_d("reset_url fail, ret = %d", ret);
    }
}

http_request::~http_request()
{
    if (_pd) {
        _deinit_private_data();
        delete _pd;
    }
}


int http_request::do_work()
{

    // 1. make request
    int ret = 0;
    ret = _make_request();
    if (ret != 0) {
        log_w("_make_request fail!");
        return -1;
    }


    // 2. connect
    ret = _write_request();


    // 3. run loop
    uv_update_time(_pd->_loop);
    uv_run(_pd->_loop, UV_RUN_DEFAULT);

    log_t("uv_run end, error_code:%hu", _pd->error_code);
    return 0;
}


int http_request::stop_work()
{
    log_d("stop_work, flag:%d", _pd->stop_flags);
    _pd->stop_flags = 1;
    return 0;
}

int http_request::_make_request()
{

    std::ostringstream ss;
    if (_pd->http_method == HTTP_GET) {
        /// GET ${PATH} ${QUERY} HTTP/1.1\r\n

        if (_pd->_req_url->get_path().size() == 0) {
            ss << "GET /";
        } else {
            ss <<"GET " << _pd->_req_url->get_path();
        }

        if (_pd->_req_url->get_query().size() > 0) {
            ss << _pd->_req_url->get_query();
        }
        ss << " HTTP/1.1\r\n";


        if (_pd->_req_url->get_port().size() == 0) {
            ss << "Host: " << _pd->_req_url->get_host() << "\r\n";
        } else {
            ss << "Host: " << _pd->_req_url->get_host() <<  ":" <<  _pd->_req_url->get_port() << "\r\n";
        }

        ss << "Accept: */*" << "\r\n";
        ss << "User-Agent: http_client_v1.0" << "\r\n";
        ss << "Connection: close" << "\r\n";
        if (_pd->_req_header) {
            ss << *(_pd->_req_header);
        }

        ss << "\r\n";
    } else if (_pd->http_method == HTTP_POST) {
        /// POST ${PATH} ${QUERY} HTTP/1.1\r\n

        if (_pd->_req_url->get_path().size() == 0) {
            ss << "POST /";
        } else {
            ss << "POST " << _pd->_req_url->get_path();
        }

        if (_pd->_req_url->get_query().size() > 0) {
            ss << _pd->_req_url->get_query();
        }

        ss << " HTTP/1.1\r\n";
        if (_pd->_req_url->get_port().size() == 0) {
            ss << "Host: " << _pd->_req_url->get_host() << "\r\n";
        } else {
            ss << "Host: " << _pd->_req_url->get_host() <<  ":" <<  _pd->_req_url->get_port() << "\r\n";
        }


        if (_pd->_req_header) {
            ss << *(_pd->_req_header);
        }

        if (_pd->_req_body && _pd->_req_body->size() > 0) {
            ss << "Content-Length: " << _pd->_req_body->size() << "\r\n";
        }

        ss << "Accept: */*" << "\r\n";
        ss << "User-Agent: http_client_v1.0" << "\r\n";
        ss << "Connection: close" << "\r\n";
        ss << "\r\n";

        if (_pd->_req_body) {
            ss << *(_pd->_req_body) << "\r\n";
        }

    } else {
        log_w("make queset unsupport type");
        return -1;
    }

    _pd->_req_buffer->clear();
    _pd->_req_buffer->append(ss.str());

    return 0;
}

int http_request::_write_request()
{
    int is_ip = 0;
    struct in_addr dst;
    if (inet_aton(_pd->_req_url->get_host().c_str(), &dst) != 0) {
        is_ip = 1;
    }

    if (is_ip) {
        int ret = _connect_to_server(_pd->_req_url->get_host().c_str(), _pd->_req_url->get_int16_port());
        if (ret != 0) {
            log_t("_connect_to_server fail, ret = %d", ret);
        }
        return ret;
    } else {
        int ret = uv_getaddrinfo(_pd->_loop, _pd->_addr, _static_uv_get_addrinfo_cb, _pd->_req_url->get_host().c_str(), NULL, NULL);
        if (ret != 0) {
            log_t("uv_getaddrinfo fail, ret = %d", ret);
        }
    }

    return 0;
}

int http_request::_connect_to_server(const char *host, int16_t port)
{
    log_t("_connect_to_server, host:%s, port:%hu", host, port);
    int ret = uv_ip4_addr(host,  port, (struct sockaddr_in*)&(_pd->_saddr));
    if (ret != 0) {
        log_t("uv_ip4_addr fail, ret=%d", ret);
        _pd->error_code = ERROR_CONNECT;
        return -1;
    }

    uv_connect_t* conn_rq = (uv_connect_t*) malloc(sizeof(uv_connect_t));
    memset(conn_rq, 0, sizeof(uv_connect_t));
    conn_rq->data = this;
    ret = uv_tcp_connect(conn_rq, _pd->_conn, (const struct sockaddr*)&_pd->_saddr, _static_uv_connect_cb);
    if (ret != 0) {
        log_t("uv_tcp_connect fail, ret=%d", ret);
        _pd->error_code = ERROR_CONNECT;
        return -1;
    }

    const int value = 1;
    int fd = _pd->_conn->io_watcher.fd;
#if defined(SO_NOSIGPIPE)
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));
#else
    setsockopt(fd, SOL_SOCKET, MSG_NOSIGNAL, &value, sizeof(value));
#endif

    if (uv_is_active((uv_handle_t*) _pd->_timer)) {
        uv_timer_stop(_pd->_timer);
    }

    ret = uv_timer_start(_pd->_timer, _static_uv_socket_timer_cb, SOCKET_TIMEOT_MS, 0);
    if (ret != 0) {
        log_t("_connect_to_server uv_timer_start failed");
    }
    return 0;
}

// private functions
int http_request::_init_private_data()
{
    _init_uv();

    _pd->_paser = (http_parser*) malloc(sizeof(http_parser));
    http_parser_init(_pd->_paser, HTTP_RESPONSE);
    _pd->_paser->data = this;


    memset(&_pd->_settings, 0, sizeof(http_parser_settings));
    _pd->_settings.on_status = &http_request::_static_parser_set_status_code;
    _pd->_settings.on_body = &http_request::_static_parser_set_resp_body;
    _pd->_settings.on_header_field = &http_request::_static_parser_header_data;


    _pd->_res_header = new http_header();
    _pd->res_buffer = new std::string();
    _pd->_req_url = new http_url();
    _pd->_req_buffer = new std::string();
    return 0;
}

int http_request::_deinit_private_data()
{
    if (_pd == NULL) {
        log_d("_pd = NULL ");
        return 0;
    }

    int ret = _deinit_uv();
    log_t("deinit_uv, ret = %d", ret);

    if (_pd->_req_buffer) {
        delete _pd->_req_buffer;
        _pd->_req_buffer = NULL;
    }

    if (_pd->_req_header) {
        delete _pd->_req_header;
        _pd->_req_header = NULL;
    }

    if (_pd->_req_body) {
        delete _pd->_req_body;
        _pd->_req_body = NULL;
    }

    if (_pd->_res_header) {
        delete _pd->_res_header;
        _pd->_res_header = NULL;
    }

    if (_pd->res_buffer) {
        delete _pd->res_buffer;
        _pd->res_buffer = NULL;
    }

    if (_pd->_paser) {
        free(_pd->_paser);
        _pd->_paser = NULL;
    }
    return 0;
}


int http_request::_init_uv()
{
    _pd->_loop = (uv_loop_t*) malloc(sizeof(uv_loop_s));
    uv_loop_init(_pd->_loop);
    _pd->_loop->data = this;

    _pd->_conn = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(_pd->_loop, _pd->_conn);
    _pd->_conn->data = this;

    _pd->_timer = (uv_timer_t*) malloc(sizeof(uv_timer_t));
    uv_timer_init(_pd->_loop, _pd->_timer);
    _pd->_timer->data = this;

    _pd->_conn_write = (uv_write_t*) malloc(sizeof(uv_write_t));
    memset(_pd->_conn_write, 0, sizeof(uv_write_t));
    _pd->_conn_write->data = this;

    _pd->_addr = (uv_getaddrinfo_t*) malloc(sizeof(uv_getaddrinfo_t));
    memset(_pd->_addr, 0, sizeof(uv_getaddrinfo_t));
    _pd->_addr->data = this;
    _pd->_addr->loop = _pd->_loop;

    return 0;
}

int http_request::_deinit_uv()
{
    if (_pd == NULL || _pd->_loop == NULL) {
        log_t("_deinit_uv already call!");
        return 0;
    }

#define STOP_UV_TIMER(x) if (uv_is_active((uv_handle_t*) x)) { uv_timer_stop(x); }

    STOP_UV_TIMER(_pd->_timer);

#undef STOP_UV_TIMER

    int ret = uv_read_stop((uv_stream_t*) _pd->_conn);
    log_d("uv_read_stop ret:%d ", ret);
    uv_stop(_pd->_loop);
    log_d("uv_stop, loop as soon as possible stop");
    uv_walk(_pd->_loop, _static_uv_walk_cb, this);
    log_d("uv_walk, loop list all fd to close");


    // FIXME: 由于uv_close异步可能未执行被执行,这里多次调用保证被执行.
    for (int i = 0; i < 10; i++) {
        ret = uv_run(_pd->_loop, UV_RUN_ONCE);
        log_d("uv_run, ret:%d UV_RUN_ONCE i = %d", ret, i);
        if (ret == 0) {
            break;
        }
    }

    ret = uv_loop_close(_pd->_loop);
    if (ret != 0) {
        log_d("uv_loop_close ret:%d ret, ret == ebusy [%d]", ret, ret == UV_EBUSY ? 1:0);
    } else {
        log_d("uv_loop_close ret == 0 succ!");
    }

    free(_pd->_loop);
    _pd->_loop = NULL;

    free(_pd->_conn);
    _pd->_conn = NULL;

    free(_pd->_timer);
    _pd->_timer = NULL;

    free(_pd->_addr);
    _pd->_addr = NULL;

    free(_pd->_conn_write);
    _pd->_conn_write = NULL;
    return 0;
}


// uv callback

void http_request::buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    log_d("buffer_alloc size:%zu", size);
    buf->base = (char*) malloc(size);
    buf->len = size;
}


void http_request::_static_uv_walk_cb(uv_handle_t* handle, void* arg)
{
    log_d("uv_walk_cb handle:%p arg:%p", handle, arg);
    if (!uv_is_closing(handle)) {
        log_d("uv_walk_cb uv_close");
        uv_close(handle, NULL);
    }
}

void http_request::_static_uv_get_addrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
#define FREE_RFINO(r)   if (r) { uv_freeaddrinfo(res); }
    if (req == NULL || req->data == NULL) {
        log_t("_static_uv_get_addrinfo_cb req = null or req->data = null");
        FREE_RFINO(res);
        return;
    }

    http_request* pthis = (http_request*) req->data;
    if (pthis->_pd->_addr != req) {
        log_t("_static_uv_get_addrinfo_cb _pd->_addr != req");
        FREE_RFINO(res);
        return;
    }

    if (status < 0) {
        log_t("_static_uv_get_addrinfo_cb fail, status=%d", status);
        FREE_RFINO(res);
        return;
    }

    const int LEN = 256;
    char buf[LEN] = {0};
    struct addrinfo * iter = res;
    for (; iter != NULL; iter = iter->ai_next) {
        memset(buf, 0, sizeof(LEN));
        if (iter->ai_family == AF_INET) {
            if (inet_ntop(iter->ai_family, &(((struct sockaddr_in*)(iter->ai_addr))->sin_addr), buf, sizeof(buf))) {
                break;
            }
        }
    }
    FREE_RFINO(res);
#undef FREE_RFINO

    if (strlen(buf) == 0) {
        log_t("_static_uv_get_addrinfo_cb resolve fail!");
        return;
    }

    int ret = pthis->_connect_to_server(buf, pthis->_pd->_req_url->get_int16_port());
    if (ret != 0) {
        log_t("_connect_to_server fail, ret = %d", ret);
    }
}


void http_request::_static_uv_connect_cb(uv_connect_t *req, int status)
{
    http_request* pthis = (http_request*) req->data;
    free(req);

    if (status == UV_ECANCELED) {
        log_t("_static_uv_connect_cb handle has been close!");
        pthis->_pd->error_code = ERROR_CONNECT;
        return;
    }

    if (status < 0) {
        log_t("_static_uv_connect_cb fail");
        pthis->_pd->error_code = ERROR_CONNECT;
        return;
    }

    int ret = -1;
    uv_buf_t buffs[1];
    buffs[0].base = (char*) pthis->_pd->_req_buffer->c_str();
    buffs[0].len = pthis->_pd->_req_buffer->length();
    ret = uv_write(pthis->_pd->_conn_write, (uv_stream_t*) pthis->_pd->_conn, buffs, 1, _static_uv_write_cb);
    if (ret != 0) {
        log_t("uv_write failed %d ", ret);
        pthis->_pd->error_code = ERROR_SOCKET_WRITE;
        return ;
    }

    if (uv_is_active((uv_handle_t*) pthis->_pd->_timer)) {
        uv_timer_stop(pthis->_pd->_timer);
    }

    ret = uv_timer_start(pthis->_pd->_timer, _static_uv_socket_timer_cb, SOCKET_TIMEOT_MS, 0);
    if (ret != 0) {
        log_t("_static_uv_connect_cb uv_timer_start failed");
    }

}

void http_request::_static_uv_write_cb(uv_write_t *req, int status)
{
    log_d("_static_uv_write_cb, status:%d", status);
    http_request* pthis = (http_request*) req->data;
    if (pthis->_pd->_conn_write != req) {
        log_t("_conn_write != req");
        pthis->_pd->error_code = ERROR_SOCKET_WRITE;
        return ;
    }

    if (status == UV_ECANCELED) {
        log_t("_static_uv_write_cb has been close");
        pthis->_pd->error_code = ERROR_SOCKET_WRITE;
        return;
    }

    if (status < 0) {
        log_t("_static_uv_write_cb error");
        pthis->_pd->error_code = ERROR_SOCKET_WRITE;
        return;
    }

    int ret = -1;
    ret = uv_read_start((uv_stream_t*)pthis->_pd->_conn, buffer_alloc, _static_uv_read_cb);
    if (ret < 0) {
        log_w("_static_uv_write_cb uv_read_start failed ! %d", ret);
        pthis->_pd->error_code = ERROR_SOCKET_READ;
    }
}


void http_request::_static_uv_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
#define FREE_BUF(b) if (b->base && b->len > 0) { free(b->base); }

    if (stream->data == NULL) {
        log_d("_static_uv_read_cb stream->data = null");
        FREE_BUF(buf);
        return;
    }

    http_request* pthis = (http_request*) stream->data;

    if (pthis->_pd->_conn != (uv_tcp_t*) stream) {
        log_n("_static_uv_read_cb _pd->_conn != stream");
        FREE_BUF(buf);
        pthis->_pd->error_code = ERROR_SOCKET_READ;
        return;
    }

    if (nread < 0) {
        log_n("_static_uv_read_cb nread < 0");

        if (nread == UV_EOF) {
            log_n("_static_uv_read_cb eof");

            if (uv_is_active((uv_handle_t*) pthis->_pd->_timer)) {
                uv_timer_stop(pthis->_pd->_timer);
            }
        }
        FREE_BUF(buf);
        return;
    }

    int ret = -1;
    if (uv_is_active((uv_handle_t*) pthis->_pd->_timer)) {
        uv_timer_stop(pthis->_pd->_timer);
    }

    ret = uv_timer_start(pthis->_pd->_timer, _static_uv_socket_timer_cb, SOCKET_TIMEOT_MS, 0);
    if (ret != 0) {
        log_t("_static_uv_read_cb uv_timer_start failed");
    }

    size_t recved = nread;
    size_t nparsed = http_parser_execute(pthis->_pd->_paser, &(pthis->_pd->_settings), buf->base, nread);

    log_d("http_parser_execute, buf:%s ", buf->base);

    if (nparsed != recved) {
        /// TODO: recv != nparsed
        log_t(" nparsed != recved, retry");
        FREE_BUF(buf);
        return ;
    }

    if (pthis->_pd->status_code != HTTP_STATUS_OK) {
        log_t("status code != 200");
    }


    if (pthis->_pd->stop_flags > 0) {
        /// stop timer
        if (uv_is_active((uv_handle_t*) pthis->_pd->_timer)) {
            uv_timer_stop(pthis->_pd->_timer);
        }

        /// stop socket
        uv_read_stop((uv_stream_t*) pthis->_pd->_conn);
    }

#undef FREE_BUF
}

void http_request::_static_uv_socket_timer_cb(uv_timer_t *handle)
{
    log_d("_static_uv_socket_timer_cb ");
    if (handle->data == NULL) {
        log_t("handle->data = null");
        return;
    }

    http_request* pthis =  (http_request*) handle->data;
    if (pthis->_pd->_timer != handle) {
        log_t("_static_uv_socket_timer_cb _pd->_timer != handle");
        return;
    }

    pthis->_pd->error_code = ERROR_TIMEOUT;

    int ret = 0;
    if (uv_is_active((uv_handle_t*) pthis->_pd->_timer)) {
        ret = uv_timer_stop(pthis->_pd->_timer);
        log_d("uv_timer_stop, ret=%d", ret);
    }

    if (uv_is_active((uv_handle_t*) pthis->_pd->_conn)) {
        ret = uv_read_stop((uv_stream_t*) pthis->_pd->_conn);
        log_d("uv_read_stop, ret=%d", ret);
    }
}






// http_parser callback
int http_request::_static_parser_set_status_code(http_parser *parser, const char *at, size_t length)
{
    http_request* pthis = (http_request*) parser->data;
    if (pthis->_pd && pthis->_pd->_paser != parser) {
        log_n("_static_parser_set_status_code paser neq");
        return 0;
    }

    pthis->_pd->status_code =  (uint16_t) std::strtol(at - 4, NULL, 10);
    log_t("status_code:%d", pthis->_pd->status_code);
    return 0;
}


int http_request::_static_parser_header_data(http_parser *parser, const char *at, size_t length)
{
    http_request* pthis = (http_request*) parser->data;
    if (pthis->_pd->_paser != parser) {
        log_d("_static_parser_header_data _pd->_paser != paser");
        return 0;
    }


    pthis->_pd->_res_header->append_data(at, length);
    return 0;
}

int http_request::_static_parser_set_resp_body(http_parser *parser, const char *at, size_t length)
{
    return 0;
}

NS_CC_END
