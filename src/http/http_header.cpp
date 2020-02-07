//
// Created by zhifan zhang on 2020/1/22.
//

#include <string.h>

#include "http/http_header.h"
#include "util/utils.h"
#include "util/logger.h"


NS_CC_BEGIN

http_header::http_header()
{
    state = kIndexName;
    headers_len = 64;
    headers_pos = 0;
    headers = (hd_data_t**) malloc(headers_len * sizeof(hd_data_t*));
    for (int i = 0; i < headers_len; i++) {
        headers[i] = (hd_data_t*) malloc(sizeof(hd_data_t));
    }
}


http_header::~http_header()
{
    log_t("http_header dctor pos:%d len:%d ", headers_pos, headers_len);
    if (headers) {
        for (int i = 0; i < headers_len; ++i) {
            if (headers[i]) {
                free(headers[i]);
                headers[i] = NULL;
            }
        }

        free(headers);
        headers = NULL;
    }
}


int http_header::append_data(const char *data, int len)
{
    if (headers_pos + 1 > headers_len) {
        int new_size = headers_len * 2;
        int ret = _expand_size(new_size);
        log_t("_expand_size ret:%d", ret);
    }

    M_ASSERT(headers_pos < headers_len, "add data fail");
    int nc = len > kMaxLen ? kMaxLen : len;

    if (state == kIndexName) {
        memset(headers[headers_pos]->name, 0, kMaxLen);
        memcpy(headers[headers_pos]->name, data, nc);
        state = kIndexValue;
        log_d("append_data name:%s, headers_pos:%d", headers[headers_pos]->name, headers_pos);
    } else if (state == kIndexValue) {
        memset(headers[headers_pos]->value, 0, kMaxLen);
        memcpy(headers[headers_pos]->value, data, nc);
        state = kIndexName;
        headers_pos++;
        log_d("append_data value:%s, len:%d headers_pos:%d", headers[headers_pos-1]->value, len, headers_pos);
    }
    return 0;
}


int http_header::add_data(const char *key, const char *val)
{
    if (headers_pos + 1 > headers_len) {
        int new_size = headers_len * 2;
        int ret = _expand_size(new_size);
        log_t("_expand_size ret:%d", ret);
    }

    M_ASSERT(headers_pos < headers_len, "add data fail");

    snprintf(headers[headers_pos]->name, ARRAY_SIZE(headers[headers_pos]->name), "%s", key);
    snprintf(headers[headers_pos]->value, ARRAY_SIZE(headers[headers_pos]->value), "%s", val);
    headers_pos++;

    log_d("add_data pos:%d key:%s val:%s", headers_pos, key, val);
    return 0;
}

std::string http_header::get_value_by_key(const char *key)
{
    std::string ret;
    if (headers_pos == 0) {
        log_d("header_value_by_key, headers_pos:%d", headers_pos);
        return ret;
    }

    for (int i = 0; i < headers_pos; ++i) {

        if (strcmp(headers[i]->name, key) == 0) {
            return  headers[i]->value;
        }

    }
    return ret;
}

int http_header::get_content_length()
{
    std::string value = get_value_by_key(HTTP_HEADER_CONTENT_LENGTH);
    if (value.size() == 0) {
        return -1;
    }

    log_d("get_content_length len:%s", value.c_str());
    int ret = std::strtol(value.c_str(), NULL, 10);
    return ret;
}

bool http_header::is_chunked_encode()
{
    std::string value = get_value_by_key(HTTP_HEADER_TRANSFER_ENCODEING);
    if (value.size() == 0) {
        return false;
    }

    utils::string_trim(value);
    log_d("Transfer-Encoding:%s", value.c_str());

    if (value.compare(HTTP_HEADER_TRANSFER_CHUNKED) == 0) {
        return true;
    }
    return false;
}

int http_header::_expand_size(int size)
{
    log_d("header_data, pos:%d len:%d", headers_pos, headers_len);
    if (headers_len > size) {
        log_t("expand_size return 0, headers_len:%d, size:%d", headers_len, size);
        return 0;
    }

    void* p = headers;
    headers = (hd_data_t**) realloc(p, size * sizeof(hd_data_t*));
    for (int i = headers_len; i < size; ++i) {
        headers[i] = (hd_data_t*) malloc(sizeof(hd_data_t));
    }

    headers_len = size;



    return 0;
}

void http_header::dump()
{
    log_d("dump begin");

    for (int i = 0; i < headers_pos; i++) {
        log_d("dump, name:%s value:%s i:%d", headers[i]->name, headers[i]->value, i);
    }

    log_d("dump end");
}


int http_header::write_to_buff(char *buf, int len)
{
    int ret = 0;
    int pos = 0;
    for (int i = 0; i < headers_pos; i++) {
        if (pos >= len) {
            log_t("write_to_buff, len < pos");
            ret = -1;
            break;
        }
        int ns = snprintf(buf + pos, len - pos, "%s: %s\r\n", headers[i]->name, headers[i]->value);
        pos += ns;
    }

    return ret == 0 ? pos : ret;
}

NS_CC_END

