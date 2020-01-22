//
// Created by zhifan zhang on 2020/1/22.
//

#include <string.h>
#include "util/logger.h"
#include "http/http_url.h"


#ifdef __cplusplus
extern "C" {
#endif

    #include "http_parser.h"

#ifdef __cplusplus
}
#endif

NS_CC_BEGIN


static const char* HTTP = "http";
static const char* HTTPS = "https";


http_url::http_url(const char* url) : _full_url(url)
{
    _host.clear();
    _query.clear();
    _path.clear();
    _port = 0;
    _state = URL_IDLE;
    int ret = _parse_url();
    if (ret == 0) {
        _state = URL_PARSEED;
    }
    log_t("_parse_url ret:%d", ret);
}

http_url::~http_url()
{

}

std::string http_url::get_full_url()
{
    return _full_url;
}

std::string http_url::get_schema()
{
    return _schema;
}

std::string http_url::get_host()
{
    return _host;
}

std::string http_url::get_path()
{
    return _path;
}

std::string http_url::get_query()
{
    return _query;
}


int16_t http_url::get_port()
{
    return _port;
}

bool http_url::is_https()
{
    return _schema.compare(HTTPS) == 0;
}


int http_url::_parse_url()
{
    if (_full_url.size() < 4) {
        log_d("_parse_url, size < 4 url:%s", _full_url.c_str());
        return -1;
    }

    log_d("_parse_url, url:%s", _full_url.c_str());

    struct http_parser_url parse;
    http_parser_url_init(&parse);
    int ret = http_parser_parse_url(_full_url.c_str(), _full_url.length(), 0, &parse);
    if (ret != 0) {
        log_t("http_parser_parse_url fail, ret:%d", ret);
        return -1;
    }


    char schema[URL_MAX_LEN] = {0};
    char host[URL_MAX_LEN] = {0};
    char port[URL_MAX_LEN] = {0};
    char path[URL_MAX_LEN] = {0};
    char query[URL_MAX_LEN] = {0};
    char fragment[URL_MAX_LEN] = {0};
    char userinfo[URL_MAX_LEN] = {0};

    if (parse.field_data[UF_SCHEMA].len > 0) {
        memcpy(schema, _full_url.c_str() + parse.field_data[UF_SCHEMA].off, parse.field_data[UF_SCHEMA].len);
    }

    if (parse.field_data[UF_HOST].len > 0) {
        memcpy(host, _full_url.c_str() + parse.field_data[UF_HOST].off, parse.field_data[UF_HOST].len);
    }

    if (parse.field_data[UF_PORT].len > 0) {
        memcpy(port, _full_url.c_str() + parse.field_data[UF_PORT].off, parse.field_data[UF_PORT].len);
    }

    if (parse.field_data[UF_PATH].len > 0) {
        memcpy(path, _full_url.c_str() + parse.field_data[UF_PATH].off, parse.field_data[UF_PATH].len);
    }

    if (parse.field_data[UF_QUERY].len > 0) {
        memcpy(query, _full_url.c_str() + parse.field_data[UF_QUERY].off, parse.field_data[UF_QUERY].len);
    }

    if (parse.field_data[UF_FRAGMENT].len > 0) {
        memcpy(fragment, _full_url.c_str() + parse.field_data[UF_FRAGMENT].off, parse.field_data[UF_FRAGMENT].len);
    }

    if (parse.field_data[UF_USERINFO].len > 0) {
        memcpy(userinfo, _full_url.c_str() + parse.field_data[UF_USERINFO].off, parse.field_data[UF_USERINFO].len);
    }

    if (strlen(schema) == 0 || strlen(host)  == 0) {
        log_t("scheam.len = 0, host.len = 0");
        return -1;
    }

    _schema = schema;
    _host = host;
    _path = path;
    _query = query;
    _fragment = fragment;
    _userinfo = userinfo;

    if (strlen(port) > 0) {
        _port = std::strtol(port, NULL, 10);
    } else if (strcmp(HTTP, schema) == 0) {
        _port = 80;
    } else if (strcmp(HTTPS, schema) == 0) {
        _port = 443;
    }

    log_d("scheam:%s host:%s path:%s query:%s fragment:%s userinfo:%s port:%d",
            schema, host, path, query, fragment, userinfo, _port);
    return 0;
}


NS_CC_END





