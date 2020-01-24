//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_HTTP_URL_H
#define UV_HTTP_HTTP_URL_H

#include <string>
#include "util/define.h"






NS_CC_BEGIN

class http_url {

public:
    http_url();

    ~http_url();

    int reset_url(const char* url);

    std::string get_full_url();

    std::string get_schema();

    std::string get_host();

    std::string get_path();

    std::string get_query();

    std::string get_port();

    int16_t get_int16_port();

    bool is_https();

private:
    enum {
        URL_IDLE = 0,
        URL_PARSEED = 1,
    };

    enum {
        URL_MAX_LEN = 1024,
    };

    int _parse_url();

private:
    std::string _full_url;
    std::string _schema;
    std::string _host;
    std::string _path;
    std::string _query;
    std::string _fragment;
    std::string _userinfo;
    std::string _port;
    int16_t     _port_i16;
    uint8_t     _state;
};


NS_CC_END

#endif //UV_HTTP_HTTP_URL_H
