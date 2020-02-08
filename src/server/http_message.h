//
// Created by zhifan zhang on 2020/2/3.
//

#ifndef UV_HTTP_HTTP_MESSAGE_H
#define UV_HTTP_HTTP_MESSAGE_H

#include <string>

#include "util/define.h"

NS_CC_BEGIN

class http_header;
class http_url;
class http_channel;
class http_message {
public:
    http_message();

    ~http_message();

    http_header* get_request_http_header();

    http_header* get_response_http_header();

    http_url* get_url();

    int make_file_response(http_channel* ch, const char* path);

    int make_simple_response(http_channel* ch, int status, const char* msg, int len, bool gzip = false);

    int make_simple_404(http_channel* ch);

    int make_simple_500(http_channel* ch);

private:
    int _make_simple_response_header();

private:
    struct buffer_data
    {
        char* data;
        int pos;
        size_t len;
    };

    struct status_code
    {
        const char* msg;
        int status;
    };



private:
    http_header* _req_header;
    http_header* _res_header;
    http_url* _url;
    buffer_data* _res_data;
    uint8_t      _keep_alive;
};


NS_CC_END

#endif //UV_HTTP_HTTP_MESSAGE_H
