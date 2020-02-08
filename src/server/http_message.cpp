//
// Created by zhifan zhang on 2020/2/3.
//

#include "server/http_message.h"
#include "server/http_channel.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "data/struct_data.h"
#include "util/logger.h"


NS_CC_BEGIN

#define DEFAULT_BUFF_LEN        (1024*4)
#define HEADER_MAX_LEN          (128)
#define HTTP_404_TPL            "\r\n\r\n \t404 Not Found"
#define HTTP_500_TPL            "\r\n\r\n \tInternal Server Error"

http_message::http_message()
{
    _req_header = new http_header();
    _res_header = new http_header();
    _url = new http_url();
    _keep_alive = 0;
    _res_data = new buffer_data();
    _res_data->len = DEFAULT_BUFF_LEN;
    _res_data->data = (char*) malloc(_res_data->len);
    _res_data->pos = 0;
}


http_message::~http_message()
{
    if (_req_header) {
        delete _req_header;
        _req_header = NULL;
    }

    if (_res_header) {
        delete _res_header;
        _res_header = NULL;
    }

    if (_url) {
        delete _url;
        _url = NULL;
    }

    if (_res_data && _res_data->data) {
        free(_res_data->data);
        _res_data->data = NULL;
    }
    if (_res_data) {
        delete _res_data;
        _res_data = NULL;
    }

    log_d("http_message dcotr");
}


http_header * http_message::get_request_http_header()
{
    return _req_header;
}

http_header * http_message::get_response_http_header()
{
    return _res_header;
}

http_url * http_message::get_url()
{
    return _url;
}


int http_message::make_simple_response(http_channel* ch, int status, const char* msg, int len)
{
    log_d("make_simple_response, status:%d, msg:%s, len:%d", status, msg, len);
    _res_data->pos = 0;
    int ns = snprintf(_res_data->data, _res_data->len, "HTTP/1.1 %d %s\r\n", status, http_status_code_msg(status));
    _res_data->pos += ns;

    char lbuf[32] = {0};
    snprintf(lbuf, ARRAY_SIZE(lbuf), "%d", len);
    _res_header->add_data(HTTP_HEADER_CONTENT_LENGTH, lbuf);
    _make_simple_response_header();

    int nw = _res_header->write_to_buff(_res_data->data + _res_data->pos, _res_data->len - _res_data->pos);
    if (nw < 0) {
        log_d("write_to_buff fail");
        return -1;
    }
    _res_data->pos += nw;

    _res_data->data[_res_data->pos++] = HTTP_CR;
    _res_data->data[_res_data->pos++] = HTTP_LF;
    memcpy(_res_data->data + _res_data->pos, msg, len);

    _res_data->pos += len;

    nw = ch->write_buff(_res_data->data, _res_data->pos, 1);
    log_d("write_buff, nw:%d", nw);
    return 0;
}

int http_message::make_simple_404(http_channel *ch)
{
    make_simple_response(ch, 404, HTTP_404_TPL, strlen(HTTP_404_TPL));
    return 0;
}

int http_message::make_simple_500(http_channel *ch)
{
    make_simple_response(ch, 500, HTTP_500_TPL, strlen(HTTP_500_TPL));
    return 0;
}

int http_message::_make_simple_response_header()
{
    // add date;
    {
        char buf[HEADER_MAX_LEN] = {0};
        time_t now = time(0);
        struct tm tm = *gmtime(&now);
        strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", &tm);
        _res_header->add_data("Date", buf);
    }

    // server
    _res_header->add_data("server", "uv_http");

    // Connection
    _res_header->add_data("Connection", _keep_alive > 0 ? "keep-alive" : "close");

    // Content-type
    _res_header->add_data("Content-Type:", "text/html;charset=UTF-8");
    return 0;
}


NS_CC_END
