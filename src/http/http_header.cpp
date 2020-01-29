//
// Created by zhifan zhang on 2020/1/22.
//

#include <string.h>

#include "http/http_header.h"
#include "util/logger.h"


NS_CC_BEGIN

http_header::http_header()
{
    state = kIndexName;
    header_index = 0;
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
//    log_d("append_data, data:%s len:%d", data, len);
    if (headers_pos + 1 > headers_len) {
        int new_size = headers_len * 2;
        int ret = _expand_size(new_size);
        log_t("_expand_size ret:%d", ret);
    }
    assert(headers_pos < headers_len);
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
        log_d("append_data value:%s, len:%d headers_pos:%d", headers[headers_pos]->value, len, headers_pos);

    }
    return 0;
}

const char* http_header::header_value_by_key(const char *key)
{
    const char* ret = "";
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


NS_CC_END

