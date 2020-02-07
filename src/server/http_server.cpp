//
// Created by zhifan zhang on 2020/2/3.
//


#include <string.h>
#include <string>

#include "server/http_server.h"
#include "server/http_channel.h"
#include "server/url_route.h"
#include "util/logger.h"

#define SERVER_TIMER_INTERVAL        (1000)

NS_CC_BEGIN

http_server::http_server()
{
    memset(&_pd, 0, sizeof(private_data));
    _channels.clear();
    log_d("http_server ctor");
}

http_server::~http_server()
{
    _deinit_private_data();
    log_d("http_server dctor");
}


int http_server::start_server(const char *ip, uint16_t port)
{
    log_d("start_server, ip:%s, port:%hu", ip, port);
    if (_pd.is_run) {
        log_d("start_server, is_run");
        return 0;
    }

    int ns = snprintf(_pd.bind_ip, ARRAY_SIZE(_pd.bind_ip), "%s", ip);
    if (ns < ARRAY_SIZE(_pd.bind_ip)) {
        _pd.bind_ip[ns] = '\0';
    }
    _pd.bind_port = port;

    int ret = 0;
    ret = _init_private_data();
    if (ret != 0) {
        log_d("_init_private_data fail");
        return -1;
    }

    _pd.is_run = THREAD_PREPARE;
    uv_thread_create(&_pd._thread, __uv_thread_entry_static, this);
    return 0;
}



int http_server::_init_private_data()
{
    int ret = 0;

    ret = _init_uv_data();
    if (ret != 0) {
        log_t("_init_uv_data fail");
        return -1;
    }


    return 0;
}


int http_server::_deinit_private_data()
{
    return 0;
}

int http_server::_init_uv_data()
{
    int ret = 0;
    _pd._loop = (uv_loop_t*) malloc(sizeof(uv_loop_s));
    memset(_pd._loop, 0, sizeof(uv_loop_s));
    _pd._loop->data = this;
    ret = uv_loop_init(_pd._loop);
    if (ret != 0) {
        log_d("uv_loop_init fail, ret:%d", ret);
        return -1;
    }

    _pd._server = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    memset(_pd._server, 0, sizeof(uv_tcp_t));
    _pd._server->data = this;
    ret = uv_tcp_init(_pd._loop, _pd._server);
    if (ret != 0) {
        log_d("uv_tcp_init fail, ret:%d", ret);
        return -1;
    }

    _pd._timer = (uv_timer_t*) malloc(sizeof(uv_timer_t));
    memset(_pd._timer, 0, sizeof(uv_timer_t));
    _pd._timer->data = this;
    ret = uv_timer_init(_pd._loop, _pd._timer);
    if (ret != 0) {
        log_d("uv_timer_init fail, ret:%d", ret);
        return -1;
    }

    ret = uv_timer_start(_pd._timer, _static_uv_timer_callback, SERVER_TIMER_INTERVAL, SERVER_TIMER_INTERVAL);
    if (ret != 0) {
        log_d("uv_timer_start fail, ret:%d", ret);
        return -1;
    }

    ret = uv_ip4_addr(_pd.bind_ip, _pd.bind_port, &_pd._saddr);
    if (ret != 0) {
        log_t("uv_ip4_addr fail, ip:%s port:%d", _pd.bind_ip, _pd.bind_port);
        return -1;
    }

    ret = uv_tcp_bind(_pd._server, (struct sockaddr*)&_pd._saddr, 0);
    if (ret != 0) {
        log_t("uv_tcp_bind fail, ret:%d", ret);
        return -1;
    }

    ret = uv_listen((uv_stream_t*)_pd._server, LISTEN_BACKLOG, _static_uv_connection_callback);
    if (ret != 0) {
        log_t("uv_listen fail");
        return -1;
    }

    _pd._route = new url_route();
    return 0;
}

int http_server::_deinit_uv_data()
{
    return 0;
}



// uv callback
void http_server::__uv_thread_entry_static(void *data)
{
    http_server* pthis = (http_server*) data;
    log_d("__uv_thread_entry_static, begin");
    pthis->_pd.is_run = THREAD_RUN;
    uv_run(pthis->_pd._loop, UV_RUN_DEFAULT);
    pthis->_pd.is_run = THREAD_END;
    log_d("__uv_thread_entry_static, end");
}

void http_server::_static_uv_timer_callback(uv_timer_t *handle)
{
    http_server* pthis = (http_server*) handle->data;

    channel_queue remove_q;
    channel_queue::iterator  it = pthis->_channels.begin();
    for ( ; it != pthis->_channels.end(); it++) {
        http_channel* ch = *it;
        int ret = ch->check_update();
        if (ret < 0) {
            remove_q.push_back(ch);
        }
    }

    while (remove_q.size()) {
        http_channel* ch = *remove_q.begin();
        it = std::find(pthis->_channels.begin(), pthis->_channels.end(), ch);
        if (it != pthis->_channels.end()) {
            pthis->_channels.erase(it);
        }
        delete ch;
        remove_q.erase(remove_q.begin());
        log_d("remove_q, size:%zu", remove_q.size());
    }
}

void http_server::_static_uv_connection_callback(uv_stream_t *server, int status)
{
    http_server* pthis = (http_server*) server->data;

    if (status < 0) {
        log_t("_static_uv_connection_callback, status:%d", status);
        return ;
    }

    http_channel* ch = new http_channel(pthis->_pd._loop);

    int ret = uv_accept(server, (uv_stream_t*) ch->get_client());
    if (ret != 0) {
        delete ch;
        log_t("uv_accept fail");
        return;
    }


    ch->start_read();
    pthis->_channels.push_back(ch);
}


NS_CC_END



