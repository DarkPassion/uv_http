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
#include "http/http_chunk.h"
#include "util/logger.h"
#include "data/write_buffer.h"
#include "data/error_code.h"
#include "data/send_data.h"

NS_CC_BEGIN


static void __uv_once_callback();

http_request::http_request(const char* url, std::string* header, std::string* body, int method)
{
    memset(&_pd, 0, sizeof(private_data));
    memset(&_callback, 0, sizeof(callback_t));

    int ret = _init_private_data();
    log_d("init_private_data, ret = %d", ret);

    _pd._req_header = header;
    _pd._req_body = body;
    _pd.http_method = method;

    ret = _pd._req_url->reset_url(url);
    if (ret != 0) {
        log_d("reset_url fail, ret = %d", ret);
    }
}

http_request::~http_request()
{
    _deinit_private_data();
}


int http_request::do_work()
{

    // 1. make request
    int ret = 0;
retry:
    ret = _make_request();
    if (ret != 0) {
        log_w("_make_request fail!");
        return -1;
    }


    // 2. connect
    ret = _write_request();
    if (ret != 0) {
        log_w("_write_request fail");
        return -1;
    }


    // 3. run loop
    uv_update_time(_pd._loop);
    uv_run(_pd._loop, UV_RUN_DEFAULT);
    log_t("uv_run end, error_code:%hu", _pd.error_code);

    if (_try_follow_location() > 0) {
        goto retry;
    }
    return 0;
}


int http_request::stop_work()
{
    log_d("stop_work, flag:%d", _pd.stop_flags);
    _pd.stop_flags = 1;
    return 0;
}

int http_request::get_result(http_result *result)
{
    if (result == NULL) {
        log_d("get_result, result = null");
        return -1;
    }
    result->error_code = 0;
    result->status_code = 0;
    result->content.clear();
    result->connect_ip[0] = '\0';


    result->status_code = _pd.status_code;
    result->error_code = _pd.error_code;
    result->content.append(*_pd.res_body);
    int ret = uv_ip4_name((struct sockaddr_in*) &_pd._saddr, result->connect_ip, ARRAY_SIZE(result->connect_ip));
    if (ret != 0) {
        log_t("uv_ip4_name, fail");
    }

    return 0;
}

int http_request::set_keep_alive(int on)
{
    log_d("set_keep_alive, on:%d", on);
    _pd.keep_alive = on;
    return 0;
}

int http_request::set_follow_location(int on)
{
    log_d("set_follow_location, on:%d", on);
    _pd.follow_location = on;
    return 0;
}


int http_request::set_write_callback(void (*cb)(const char* buf, size_t len, void* data), void *user)
{
    log_d("set_write_callback, cb:%p, user:%p", cb, user);
    _callback.wcb = cb;
    _callback.wcb_data = user;
    return 0;
}

int http_request::set_response_callback(void (*cb)(int error, http_request* request, void* data), void *user)
{
    log_d("set_response_callback, cb:%p, user:%p", cb, user);
    _callback.rcb = cb;
    _callback.rcb_data = user;
    return 0;
}

int http_request::set_notify_callback(void (*cb)(int, const char *, size_t, void *), void *user)
{
    log_d("set_notify_callback, cb:%p, user:%p", cb, user);

    _callback.ncb = cb;
    _callback.ncb_data = user;
    return 0;
}

int http_request::_make_request()
{

    std::ostringstream ss;
    if (_pd.http_method == HTTP_GET) {
        /// GET ${PATH} ${QUERY} HTTP/1.1\r\n

        if (_pd._req_url->get_path().size() == 0) {
            ss << "GET /";
        } else {
            ss <<"GET " << _pd._req_url->get_path();
        }

        if (_pd._req_url->get_query().size() > 0) {
            if (_pd._req_url->get_query().at(0) != '?') {
                ss << "?";
            }
            ss << _pd._req_url->get_query();
        }
        ss << " HTTP/1.1\r\n";


        if (_pd._req_url->get_port().size() == 0) {
            ss << "Host: " << _pd._req_url->get_host() << "\r\n";
        } else {
            ss << "Host: " << _pd._req_url->get_host() <<  ":" <<  _pd._req_url->get_port() << "\r\n";
        }

        ss << "Accept: */*" << "\r\n";
        ss << "User-Agent: http_client_v1.0" << "\r\n";
        if (_pd.keep_alive) {
            ss << "Connection: keep-alive" << "\r\n";
        } else {
            ss << "Connection: close" << "\r\n";
        }
        if (_pd._req_header) {
            ss << *(_pd._req_header);
        }

        ss << "\r\n";
    } else if (_pd.http_method == HTTP_POST) {
        /// POST ${PATH} ${QUERY} HTTP/1.1\r\n

        if (_pd._req_url->get_path().size() == 0) {
            ss << "POST /";
        } else {
            ss << "POST " << _pd._req_url->get_path();
        }

        if (_pd._req_url->get_query().size() > 0) {
            if (_pd._req_url->get_query().at(0) != '?') {
                ss << "?";
            }
            ss << _pd._req_url->get_query();
        }

        ss << " HTTP/1.1\r\n";
        if (_pd._req_url->get_port().size() == 0) {
            ss << "Host: " << _pd._req_url->get_host() << "\r\n";
        } else {
            ss << "Host: " << _pd._req_url->get_host() <<  ":" <<  _pd._req_url->get_port() << "\r\n";
        }


        if (_pd._req_header) {
            ss << *(_pd._req_header);
        }

        if (_pd._req_body && _pd._req_body->size() > 0) {
            ss << "Content-Length: " << _pd._req_body->size() << "\r\n";
        }

        ss << "Accept: */*" << "\r\n";
        ss << "User-Agent: http_client_v1.0" << "\r\n";
        if (_pd.keep_alive) {
            ss << "Connection: keep-alive" << "\r\n";
        } else {
            ss << "Connection: close" << "\r\n";
        }
        ss << "\r\n";

        if (_pd._req_body) {
            ss << *(_pd._req_body) << "\r\n";
        }

    } else {
        log_w("make queset unsupport type");
        return -1;
    }

    _pd._req_buffer->clear();
    _pd._req_buffer->append(ss.str());

    log_d("make_request, req_buffer: %s", _pd._req_buffer->c_str());
    return 0;
}

int http_request::_write_request()
{
    int is_ip = 0;
    struct in_addr dst;
    if (inet_aton(_pd._req_url->get_host().c_str(), &dst) != 0) {
        is_ip = 1;
    }

    if (is_ip) {
        int ret = _connect_to_server(_pd._req_url->get_host().c_str(), _pd._req_url->get_int16_port());
        if (ret != 0) {
            log_t("_connect_to_server fail, ret = %d", ret);
        }
        return ret;
    } else {
        int ret = uv_getaddrinfo(_pd._loop, _pd._addr, _static_uv_get_addrinfo_cb, _pd._req_url->get_host().c_str(), NULL, NULL);
        if (ret != 0) {
            log_t("uv_getaddrinfo fail, ret = %d", ret);
            _pd.error_code = ERROR_DNS_RESOLVE;
        }
    }

    return 0;
}

int http_request::_connect_to_server(const char *host, int16_t port)
{
    log_t("_connect_to_server, host:%s, port:%hu", host, port);
    int ret = uv_ip4_addr(host,  port, (struct sockaddr_in*)&(_pd._saddr));
    if (ret != 0) {
        log_t("uv_ip4_addr fail, ret=%d", ret);
        _pd.error_code = ERROR_CONNECT;
        return -1;
    }

    uv_connect_t* conn_rq = (uv_connect_t*) malloc(sizeof(uv_connect_t));
    memset(conn_rq, 0, sizeof(uv_connect_t));
    conn_rq->data = this;
    ret = uv_tcp_connect(conn_rq, _pd._conn, (const struct sockaddr*)&_pd._saddr, _static_uv_connect_cb);
    if (ret != 0) {
        log_t("uv_tcp_connect fail, ret=%d", ret);
        _pd.error_code = ERROR_CONNECT;
        return -1;
    }

    const int value = 1;
    int fd = _pd._conn->io_watcher.fd;
#if defined(SO_NOSIGPIPE)
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));
#else
    setsockopt(fd, SOL_SOCKET, MSG_NOSIGNAL, &value, sizeof(value));
#endif

    if (uv_is_active((uv_handle_t*) _pd._timer)) {
        uv_timer_stop(_pd._timer);
    }

    ret = uv_timer_start(_pd._timer, _static_uv_socket_timer_cb, SOCKET_TIMEOUT_MS, 0);
    if (ret != 0) {
        log_t("_connect_to_server uv_timer_start failed");
    }
    return 0;
}

int http_request::_try_follow_location()
{
    log_d("_try_follow_location, status_code:%d, location:%s", _pd.status_code, _pd._res_header->get_value_by_key(HTTP_HEADER_LOCATION).c_str());

    int ret = 0;
    std::string location_url = _pd._res_header->get_value_by_key(HTTP_HEADER_LOCATION);

    // 1. follow_location > 0
    // 2. 301
    // 3. 302
    if (_pd.follow_location > 0 &&
        location_url.size() > 0 &&
        (_pd.status_code == HTTP_STATUS_MOVED_PERMANENTLY || _pd.status_code == HTTP_STATUS_FOUND)) {
        private_data my_pd;
        memset(&my_pd, 0, sizeof(private_data));

#define SET_PD_FIELD_PTR(x)    { my_pd.x = _pd.x; _pd.x = NULL; }
#define SET_PD_FIELD_INT(x)    { my_pd.x = _pd.x; }

#define GET_PD_FIELD_PTR(x)    { _pd.x = my_pd.x; my_pd.x = NULL; }
#define GET_PD_FIELD_INT(x)    { _pd.x = my_pd.x; }

        SET_PD_FIELD_INT(http_method);
        SET_PD_FIELD_PTR(_req_header);
        SET_PD_FIELD_PTR(_req_body);


        http_url my_url;
        ret = my_url.reset_url(location_url.c_str());
        if (ret != 0) {
            log_t("my_url.reset_url fail, ret:%d", ret);

            // location with relative path
            if (location_url.at(0) == '/') {
                std::string new_url;
                new_url.append(_pd._req_url->get_schema());
                new_url.append("://");
                new_url.append(_pd._req_url->get_host());
                if (_pd._req_url->get_port().size() > 0) {
                    new_url.append(":");
                    new_url.append(_pd._req_url->get_port());
                    new_url.append(location_url);
                }

                location_url = new_url;
            } else {
                return -1;
            }
        }

        ret = _deinit_private_data();
        log_d("_try_follow_location, _deinit_private_data ret=%d", ret);

        ret = _init_private_data();
        log_d("_try_follow_location, _init_private_data ret = %d", ret);

        GET_PD_FIELD_INT(http_method);
        GET_PD_FIELD_PTR(_req_header);
        GET_PD_FIELD_PTR(_req_body);

        _pd._req_url->reset_url(location_url.c_str());
        return 1;
    }

#undef GET_PD_FIELD_INT
#undef GET_PD_FIELD_PTR

#undef SET_PD_FIELD_PTR
#undef SET_PD_FIELD_INT
    return ret;
}

static void __uv_once_callback()
{
    SSL_library_init();
    SSL_load_error_strings();
}

int http_request::_init_ssl_trans()
{
    if (_pd._trans) {
        return 0;
    }

    static uv_once_t once;
    uv_once(&once, __uv_once_callback);


    _pd._trans = new ssl_trans();
    memset(_pd._trans, 0, sizeof(ssl_trans));

    _pd._trans->ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(_pd._trans->ctx, SSL_OP_NO_SSLv2);

    _pd._trans->ssl = SSL_new(_pd._trans->ctx);
    _pd._trans->read_bio = BIO_new(BIO_s_mem());
    _pd._trans->write_bio = BIO_new(BIO_s_mem());
    _pd._trans->wb = new write_buffer();

    SSL_set_bio(_pd._trans->ssl, _pd._trans->read_bio, _pd._trans->write_bio);

    log_d("_init_ssl_trans");
    return 0;
}


int http_request::_deinit_ssl_trans()
{
    if (_pd._trans == NULL) {
        return 0;
    }
    log_d("_deinit_ssl_trans");
    SSL_CTX_free(_pd._trans->ctx);
    SSL_free(_pd._trans->ssl);

    if (_pd._trans->wb) {
        delete _pd._trans->wb;
        _pd._trans->wb = NULL;
    }

    _pd._trans->ctx = NULL;
    _pd._trans->ssl = NULL;

    _pd._trans->read_bio = NULL;
    _pd._trans->write_bio = NULL;
    delete _pd._trans;
    _pd._trans = NULL;
    return 0;
}

int http_request::_ssl_trans_check_write_data()
{
    log_d("_ssl_trans_check_write_data");

    if(SSL_is_init_finished(_pd._trans->ssl)) {
        if ( _pd._req_buffer->size() > 0 && _pd._trans->send_req == 0) {
            _pd._trans->send_req = 1;
            int r = SSL_write(_pd._trans->ssl, _pd._req_buffer->c_str(), _pd._req_buffer->size());
            log_d("SSL_write, r:%d", r);
            _ssl_trans_handle_error(r);
            _ssl_trans_flush_read_bio();
        }
    }
    return 0;
}

int http_request::_ssl_trans_cycle()
{
    char buf[1024 * 4] = {0};
    int bytes_read = 0;
    if(!SSL_is_init_finished(_pd._trans->ssl)) {
        log_d("_ssl_trans_cycle SSL_is_init_finished:0");
        int r = SSL_connect(_pd._trans->ssl);
        if(r < 0) {
            _ssl_trans_handle_error(r);
        }
        _ssl_trans_check_write_data();
    } else {
        log_d("_ssl_trans_cycle SSL_is_init_finished:1");
        // connect, check if there is encrypted data, or we need to send app data
        int r = SSL_read(_pd._trans->ssl, buf, sizeof(buf));
        if(r < 0) {
            _ssl_trans_handle_error(r);
        } else if(r > 0) {
            log_d("SSL_read, buf:%s", buf);
            r = _input_http_parser_data(buf, r);
            if (r != 0) {
                log_t("_input_http_parser_data fail, ret:%d", r);
            }
        }
        _ssl_trans_check_write_data();
    }
    return 0;
}


int http_request::_ssl_trans_handle_error(int result)
{
    int error = SSL_get_error(_pd._trans->ssl, result);
    if(error == SSL_ERROR_WANT_READ) { // wants to read from bio
        _ssl_trans_flush_read_bio();
    }
    return 0;
}

int http_request::_ssl_trans_flush_read_bio()
{
    log_d("_ssl_trans_flush_read_bio ");

    uint8_t* wb_data = NULL;
    uint32_t wb_data_len = 0;
    _pd._trans->wb->malloc_buffer(&wb_data, wb_data_len);
    int bytes_read = 0;
    while((bytes_read = BIO_read(_pd._trans->write_bio, wb_data, wb_data_len)) > 0) {
        log_d("BIO_read, bytes_read:%d, size:%d", bytes_read, wb_data_len);
        int ret = -1;
        send_data* __send = new send_data;
        memset(__send, 0, sizeof(send_data));
        __send->write.data = __send;
        __send->data = this;
        __send->buf.base = (char*) wb_data;
        __send->buf.len = bytes_read;

        ret = uv_write(&__send->write, (uv_stream_t*) _pd._conn, &__send->buf, 1, _static_uv_write_cb);
        if (ret != 0) {
            log_t("uv_write failed %d ", ret);
            _pd.error_code = ERROR_SOCKET_WRITE;
            return -1;
        }

        if (uv_is_active((uv_handle_t*) _pd._timer)) {
            uv_timer_stop(_pd._timer);
        }

        ret = uv_timer_start(_pd._timer, _static_uv_socket_timer_cb, SOCKET_TIMEOUT_MS, 0);
        if (ret != 0) {
            log_t("_static_uv_connect_cb uv_timer_start failed");
        }

        _pd._trans->wb->malloc_buffer(&wb_data, wb_data_len);
    }

    int ret = _pd._trans->wb->free_buffer(wb_data);
    log_d("wb->free_buffer, ret:%d", ret);

    return 0;
}

int http_request::_ssl_trans_handle_disconnect()
{
    log_d("_ssl_trans_handle_disconnect ");
    if (!SSL_is_init_finished(_pd._trans->ssl)) {
        log_d("_ssl_trans_handle_disconnect, hands shake fail");
        return 0;
    }

    // read ssl left data
    char buf[1024 * 4] = {0};
    int r = SSL_read(_pd._trans->ssl, buf, sizeof(buf));
    if(r < 0) {
        _ssl_trans_handle_error(r);
    } else if(r > 0) {
        log_d("SSL_read, buf:%s", buf);
        r = _input_http_parser_data(buf, r);
        if (r != 0) {
            log_t("_input_http_parser_data fail, ret:%d", r);
        }
    }
    return 0;
}


// private functions
int http_request::_init_private_data()
{
    _init_uv();

    _pd._paser = (http_parser*) malloc(sizeof(http_parser));
    http_parser_init(_pd._paser, HTTP_RESPONSE);
    _pd._paser->data = this;


    memset(&_pd._settings, 0, sizeof(http_parser_settings));
    _pd._settings.on_status = &http_request::_static_parser_set_status_code;
    _pd._settings.on_body = &http_request::_static_parser_set_resp_body;
    _pd._settings.on_header_field = &http_request::_static_parser_header_data;
    _pd._settings.on_header_value = &http_request::_static_parser_header_data;

    _pd._chunk = new http_chunk();
    _pd._res_header = new http_header();
    _pd.res_body = new std::string();
    _pd._req_url = new http_url();
    _pd._req_buffer = new std::string();
    return 0;
}

int http_request::_deinit_private_data()
{
    int ret = _deinit_uv();
    log_t("deinit_uv, ret = %d", ret);

    ret = _deinit_ssl_trans();
    log_t("_deinit_ssl_trans, ret = %d", ret);

    if (_pd._chunk) {
        delete _pd._chunk;
        _pd._chunk = NULL;
    }

    if (_pd._req_buffer) {
        delete _pd._req_buffer;
        _pd._req_buffer = NULL;
    }

    if (_pd._req_header) {
        delete _pd._req_header;
        _pd._req_header = NULL;
    }

    if (_pd._req_body) {
        delete _pd._req_body;
        _pd._req_body = NULL;
    }

    if (_pd._res_header) {
        delete _pd._res_header;
        _pd._res_header = NULL;
    }

    if (_pd.res_body) {
        delete _pd.res_body;
        _pd.res_body = NULL;
    }

    if (_pd._req_url) {
        delete _pd._req_url;
        _pd._req_url = NULL;
    }

    if (_pd._paser) {
        free(_pd._paser);
        _pd._paser = NULL;
    }
    return 0;
}


int http_request::_init_uv()
{
    _pd._loop = (uv_loop_t*) malloc(sizeof(uv_loop_s));
    uv_loop_init(_pd._loop);
    _pd._loop->data = this;

    _pd._conn = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(_pd._loop, _pd._conn);
    _pd._conn->data = this;

    _pd._timer = (uv_timer_t*) malloc(sizeof(uv_timer_t));
    uv_timer_init(_pd._loop, _pd._timer);
    _pd._timer->data = this;


    _pd._addr = (uv_getaddrinfo_t*) malloc(sizeof(uv_getaddrinfo_t));
    memset(_pd._addr, 0, sizeof(uv_getaddrinfo_t));
    _pd._addr->data = this;
    _pd._addr->loop = _pd._loop;

    return 0;
}

int http_request::_deinit_uv()
{
    if (_pd._loop == NULL) {
        log_t("_deinit_uv already call!");
        return 0;
    }

#define STOP_UV_TIMER(x) if (uv_is_active((uv_handle_t*) x)) { uv_timer_stop(x); }

    STOP_UV_TIMER(_pd._timer);

#undef STOP_UV_TIMER

    int ret = uv_read_stop((uv_stream_t*) _pd._conn);
    log_d("uv_read_stop ret:%d ", ret);
    uv_stop(_pd._loop);
    log_d("uv_stop, loop as soon as possible stop");
    uv_walk(_pd._loop, _static_uv_walk_cb, this);
    log_d("uv_walk, loop list all fd to close");


    // FIXME: 由于uv_close异步可能未执行被执行,这里多次调用保证被执行.
    for (int i = 0; i < 10; i++) {
        ret = uv_run(_pd._loop, UV_RUN_ONCE);
        log_d("uv_run, ret:%d UV_RUN_ONCE i = %d", ret, i);
        if (ret == 0) {
            break;
        }
    }

    ret = uv_loop_close(_pd._loop);
    if (ret != 0) {
        log_d("uv_loop_close ret:%d ret, ret == ebusy [%d]", ret, ret == UV_EBUSY ? 1:0);
    } else {
        log_d("uv_loop_close ret == 0 succ!");
    }

    free(_pd._loop);
    _pd._loop = NULL;

    free(_pd._conn);
    _pd._conn = NULL;

    free(_pd._timer);
    _pd._timer = NULL;

    free(_pd._addr);
    _pd._addr = NULL;

    return 0;
}


int http_request::_input_http_parser_data(const char *data, int len)
{
    int ret = -1;
    size_t nparsed = http_parser_execute(_pd._paser, &(_pd._settings), data, len);
    log_d("http_parser_execute, buf:%s ", data);

    if (nparsed != len) {
        /// TODO: recv != nparsed
        log_t(" nparsed != recved, retry");
        return -1;
    }

    ret = _pd._chunk->input_encode_data(data, len);
    if (ret != 0) {
        log_t("http_chunk.input_data fail, ret:%d", ret);
    }

    // content-length
    bool is_eof = false;
    if (_pd._res_header->get_content_length() > 0 &&
        _pd._res_header->get_content_length() == _pd.res_body->size()) {
        log_d("content-length:%d, http_body eq content-length", _pd._res_header->get_content_length());
        is_eof = true;
    }

    if (_pd.stop_flags > 0 || _pd._chunk->is_eof() || is_eof) {
        log_d("stop_flags:%d chunk_is_eof:%d ", _pd.stop_flags, _pd._chunk->is_eof());
        /// stop timer
        if (uv_is_active((uv_handle_t*) _pd._timer)) {
            uv_timer_stop(_pd._timer);
        }

        /// stop socket
        uv_read_stop((uv_stream_t*) _pd._conn);
    }
    return 0;
}

// uv callback

void http_request::buffer_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    log_d("buffer_alloc size:%zu", size);
    buf->base = (char*) malloc(size);
    buf->len = size;
}

void http_request::_static_uv_close_cb(uv_handle_t *handle)
{
    log_d("_static_uv_close_cb, handle:%p", handle);
}

void http_request::_static_uv_walk_cb(uv_handle_t* handle, void* arg)
{
    log_d("uv_walk_cb handle:%p arg:%p", handle, arg);
    if (!uv_is_closing(handle)) {
        log_d("uv_walk_cb uv_close");
        uv_close(handle, _static_uv_close_cb);
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
    if (pthis->_pd._addr != req) {
        log_t("_static_uv_get_addrinfo_cb _pd._addr != req");
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

    int ret = pthis->_connect_to_server(buf, pthis->_pd._req_url->get_int16_port());
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
        pthis->_pd.error_code = ERROR_CONNECT;
        return;
    }

    if (status < 0) {
        log_t("_static_uv_connect_cb fail");
        pthis->_pd.error_code = ERROR_CONNECT;
        return;
    }

    int ret = 0;
    if (pthis->_callback.ncb) {
        char ipv4[64] = {0};
        ret = uv_ip4_name((struct sockaddr_in*) &pthis->_pd._saddr, ipv4, ARRAY_SIZE(ipv4));
        if (ret == 0) {
            pthis->_callback.ncb(NOTIFY_CONNECT_IP, ipv4, strlen(ipv4), pthis->_callback.ncb_data);
        }
    }

    // is https;
    if (pthis->_pd._req_url->is_https()) {
        ret = pthis->_init_ssl_trans();
        log_d("_init_ssl_trans, ret:%d", ret);

        SSL_set_connect_state(pthis->_pd._trans->ssl);
        ret = SSL_do_handshake(pthis->_pd._trans->ssl);
        log_d("SSL_do_handshake, ret:%d", ret);
        pthis->_ssl_trans_cycle();
        return ;
    }

    uv_buf_t buffs[1];
    buffs[0].base = (char*) pthis->_pd._req_buffer->c_str();
    buffs[0].len = pthis->_pd._req_buffer->length();
    send_data* wb = new send_data;
    memset(wb, 0, sizeof(send_data));
    wb->write.data = wb;
    wb->data = pthis;

    ret = uv_write(&wb->write, (uv_stream_t*) pthis->_pd._conn, buffs, 1, _static_uv_write_cb);
    if (ret != 0) {
        log_t("uv_write failed %d ", ret);
        pthis->_pd.error_code = ERROR_SOCKET_WRITE;
        return ;
    }

    if (uv_is_active((uv_handle_t*) pthis->_pd._timer)) {
        uv_timer_stop(pthis->_pd._timer);
    }

    ret = uv_timer_start(pthis->_pd._timer, _static_uv_socket_timer_cb, SOCKET_TIMEOUT_MS, 0);
    if (ret != 0) {
        log_t("_static_uv_connect_cb uv_timer_start failed");
    }
}

void http_request::_static_uv_write_cb(uv_write_t *req, int status)
{
    log_d("_static_uv_write_cb, status:%d", status);
    send_data* __send = (send_data*) req->data;
    http_request* pthis = (http_request*) __send->data;

    if (__send->buf.base != NULL && __send->buf.len > 0 && pthis && pthis->_pd._trans) {
        int ret = pthis->_pd._trans->wb->free_buffer((uint8_t*) __send->buf.base);
        log_d("_static_uv_write_cb free_buffer ret:%d", ret);
    }
    send_data_destory(&__send);

    if (status == UV_ECANCELED) {
        log_t("_static_uv_write_cb has been close");
        pthis->_pd.error_code = ERROR_SOCKET_WRITE;
        return;
    }

    if (status < 0) {
        log_t("_static_uv_write_cb error");
        pthis->_pd.error_code = ERROR_SOCKET_WRITE;
        return;
    }

    int ret = -1;
    ret = uv_read_start((uv_stream_t*)pthis->_pd._conn, buffer_alloc, _static_uv_read_cb);
    if (ret < 0) {
        log_w("_static_uv_write_cb uv_read_start failed ! %d", ret);
        pthis->_pd.error_code = ERROR_SOCKET_READ;
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

    if (pthis->_pd._conn != (uv_tcp_t*) stream) {
        log_n("_static_uv_read_cb _pd._conn != stream");
        FREE_BUF(buf);
        pthis->_pd.error_code = ERROR_SOCKET_READ;
        return;
    }

    if (nread < 0) {
        log_n("_static_uv_read_cb nread < 0");

        if (nread == UV_EOF) {
            log_n("_static_uv_read_cb eof");

            if (uv_is_active((uv_handle_t*) pthis->_pd._timer)) {
                uv_timer_stop(pthis->_pd._timer);
            }
        }

        pthis->_ssl_trans_handle_disconnect();

        FREE_BUF(buf);
        return;
    }

    int ret = -1;
    if (uv_is_active((uv_handle_t*) pthis->_pd._timer)) {
        uv_timer_stop(pthis->_pd._timer);
    }

    ret = uv_timer_start(pthis->_pd._timer, _static_uv_socket_timer_cb, SOCKET_TIMEOUT_MS, 0);
    if (ret != 0) {
        log_t("_static_uv_read_cb uv_timer_start failed");
    }

    if (pthis->_pd._req_url->is_https()) {
        int nwrite = BIO_write(pthis->_pd._trans->read_bio, buf->base, nread);
        log_d("BIO_write, nwrite:%d", nwrite);
        FREE_BUF(buf);

        pthis->_ssl_trans_cycle();
        return ;
    }

    ret = pthis->_input_http_parser_data(buf->base, nread);
    if (ret != 0) {
        log_t("_input_http_parser_data fail, ret:%d", ret);
    }

    FREE_BUF(buf);

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
    if (pthis->_pd._timer != handle) {
        log_t("_static_uv_socket_timer_cb _pd._timer != handle");
        return;
    }

    pthis->_pd.error_code = ERROR_TIMEOUT;

    int ret = 0;
    if (uv_is_active((uv_handle_t*) pthis->_pd._timer)) {
        ret = uv_timer_stop(pthis->_pd._timer);
        log_d("uv_timer_stop, ret=%d", ret);
    }

    if (uv_is_active((uv_handle_t*) pthis->_pd._conn)) {
        ret = uv_read_stop((uv_stream_t*) pthis->_pd._conn);
        log_d("uv_read_stop, ret=%d", ret);
    }
}



// http_parser callback
int http_request::_static_parser_set_status_code(http_parser *parser, const char *at, size_t length)
{
    http_request* pthis = (http_request*) parser->data;
    if (pthis->_pd._paser != parser) {
        log_n("_static_parser_set_status_code paser neq");
        return 0;
    }

    pthis->_pd.status_code =  (uint16_t) std::strtol(at - 4, NULL, 10);
    log_t("status_code:%d", pthis->_pd.status_code);

    if (pthis->_callback.ncb) {
        char status_code_buf[64] = {0};
        snprintf(status_code_buf,
                ARRAY_SIZE(status_code_buf),
                "%d", pthis->_pd.status_code);

        pthis->_callback.ncb(NOTIFY_STATUS_CODE, status_code_buf, strlen(status_code_buf), pthis->_callback.ncb_data);
    }
    return 0;
}


int http_request::_static_parser_header_data(http_parser *parser, const char *at, size_t length)
{
    http_request* pthis = (http_request*) parser->data;
    if (pthis->_pd._paser != parser) {
        log_d("_static_parser_header_data _pd._paser != paser");
        return 0;
    }


    pthis->_pd._res_header->append_data(at, length);
    return 0;
}

int http_request::_static_parser_set_resp_body(http_parser *parser, const char *at, size_t length)
{
    http_request* pthis = (http_request*) parser->data;
    if (pthis->_pd._paser != parser) {
        log_d("_static_parser_set_resp_body _pd._paser != paser");
        return 0;
    }

    // chunk encode body too large!
    if (/*pthis->_pd._chunk->is_chunk_encode() == 0 &&*/ pthis->_callback.wcb == NULL && pthis->_pd._res_header->get_content_length() > 0) {
        pthis->_pd.res_body->append(at, length);
    }

    if (pthis->_callback.wcb) {
        pthis->_callback.wcb(at, length, pthis->_callback.wcb_data);
    }
    return 0;
}

NS_CC_END
