//
// Created by zhifan zhang on 2020/2/3.
//

#include <sys/stat.h>
#include "server/http_message.h"
#include "server/http_channel.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "data/send_data.h"
#include "data/http_code.h"
#include "util/utils.h"
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

int http_message::make_file_response(http_channel *ch, const char *path)
{
    log_d("make_file_response, path:%s", path);

    struct stat st;
    if (stat(path, &st) != 0) {
        return make_simple_404(ch);
    }

    static const uint32_t frag = 1024;
    log_d("make_file_response, size:%zu", st.st_size);
    int ns = 0;
    _res_data->pos = 0;

    ns = snprintf(_res_data->data, _res_data->len, "HTTP/1.1 %d %s\r\n", HTTP_STATUS_OK, http_status_code_msg(HTTP_STATUS_OK));
    _res_data->pos += ns;

    _res_header->add_data(HTTP_HEADER_TRANSFER_ENCODEING, HTTP_HEADER_TRANSFER_CHUNKED);
    _make_simple_response_header();
    const char* ext = strrchr(path, '.');
    if (ext != NULL) {
        _res_header->add_data(HTTP_HEADER_CONTENT_TYPE, http_content_type(ext+1));
    }


    int nw = _res_header->write_to_buff(_res_data->data + _res_data->pos, _res_data->len - _res_data->pos);
    if (nw < 0) {
        log_d("write_to_buff fail");
        return -1;
    }
    _res_data->pos += nw;

    _res_data->data[_res_data->pos++] = HTTP_CR;
    _res_data->data[_res_data->pos++] = HTTP_LF;


    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        log_d("fopen fail");
        return -1;
    }
    uint32_t chunk_size = st.st_size;


    while (chunk_size > 0) {
        int nc = chunk_size > frag ? frag : chunk_size;

        // chunk size
        char* in = _res_data->data + _res_data->pos;
        ns = snprintf(_res_data->data + _res_data->pos, _res_data->len - _res_data->pos, "%x", nc);
        _res_data->pos += ns;
        log_d("make_file_response,  ns:%d, chunk_size:%u", ns, nc);
        _res_data->data[_res_data->pos++] = HTTP_CR;
        _res_data->data[_res_data->pos++] = HTTP_LF;

        // chunk data
        ns = fread(_res_data->data + _res_data->pos, nc, 1, fp);
        M_ASSERT(ns > 0, "fread > 0 fail");
        log_d("make_file_response, fread:%d", ns);
        _res_data->pos += nc;
        _res_data->data[_res_data->pos++] = HTTP_CR;
        _res_data->data[_res_data->pos++] = HTTP_LF;

        chunk_size -= nc;
    }
    fclose(fp);


    // end chunk
    _res_data->data[_res_data->pos++] = '0';
    _res_data->data[_res_data->pos++] = HTTP_CR;
    _res_data->data[_res_data->pos++] = HTTP_LF;
    _res_data->data[_res_data->pos++] = HTTP_CR;
    _res_data->data[_res_data->pos++] = HTTP_LF;

    send_data* sed = ch->_pd._sed_q->new_data();
    sed->nbuf = 1;
    sed->buf[0].base = _res_data->data;
    sed->buf[0].len = _res_data->len;
    sed->data = ch;
    sed->write.data = sed;
    nw = ch->write_buff(sed, 1);
    if (nw < 0) {
        delete sed;
        log_d("write_buff fail");
    }
    return 0;
}


int http_message::make_simple_response(http_channel* ch, int status, const char* msg, int len, bool gzip)
{
    log_d("make_simple_response, status:%d, msg:%s, len:%d", status, msg, len);
    _res_data->pos = 0;
    int ns = snprintf(_res_data->data, _res_data->len, "HTTP/1.1 %d %s\r\n", status, http_status_code_msg(status));
    _res_data->pos += ns;

    std::string html_msg;
    html_msg.append(msg, len);
    utils::string_html_encode(html_msg);
    log_d("make_simple_response, html_msg:%s", html_msg.c_str());

    _make_simple_response_header();
    std::string encode_msg;
    if (gzip) {
        utils::gzip_encode(html_msg, encode_msg);
        _res_header->add_data(HTTP_HREADER_CONTENT_ENCODING, HTTP_HREADER_ENCODING_GZIP);
        _res_header->add_data(HTTP_HEADER_CONTENT_LENGTH, utils::string_format("%zu", encode_msg.size()).c_str());
    } else {
        _res_header->add_data(HTTP_HEADER_CONTENT_LENGTH, utils::string_format("%zu", html_msg.size()).c_str());
    }

    int nw = _res_header->write_to_buff(_res_data->data + _res_data->pos, _res_data->len - _res_data->pos);
    if (nw < 0) {
        log_d("write_to_buff fail");
        return -1;
    }
    _res_data->pos += nw;

    _res_data->data[_res_data->pos++] = HTTP_CR;
    _res_data->data[_res_data->pos++] = HTTP_LF;

    if (gzip) {
        memcpy(_res_data->data + _res_data->pos, encode_msg.data(), encode_msg.size());
        _res_data->pos += encode_msg.size();
    } else {
        memcpy(_res_data->data + _res_data->pos, html_msg.data(), html_msg.size());
        _res_data->pos += html_msg.size();
    }

    send_data* sed = new send_data();
    sed->nbuf = 1;
    sed->buf[0].base = _res_data->data;
    sed->buf[0].len = _res_data->len;
    sed->data = ch;
    sed->write.data = sed;
    nw = ch->write_buff(sed, 1);
    if (nw < 0) {
        delete sed;
        log_d("write_buff fail");
    }
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
    _res_header->add_data(HTTP_HEADER_CONNECTION, _keep_alive > 0 ? HTTP_HEADER_CONNECTION_KEEP_ALIVE : HTTP_HEADER_CONNECTION_CLOSE);

    // Content-type
    _res_header->add_data(HTTP_HEADER_CONTENT_TYPE, "text/html;charset=UTF-8");
    return 0;
}


NS_CC_END
