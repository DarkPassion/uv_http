//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_HTTP_HEADER_H
#define UV_HTTP_HTTP_HEADER_H

#include "util/define.h"



NS_CC_BEGIN

class http_header {
public:
    http_header();

    ~http_header();


    int append_data(const char* data, int len);

    const char* header_value_by_key(const char* key);

    void dump();
public:

    enum {
        kIndexName = 0,
        kIndexValue,
    };

    int _expand_size(int size);
private:

    enum {
        kMaxLen = 256,
    };


    struct hd_data_t
    {
        char name[kMaxLen];
        char value[kMaxLen];
    };


private:
    uint8_t     header_index;
    uint8_t     state;
    int         headers_pos;
    int         headers_len;
    struct hd_data_t** headers;
};

NS_CC_END

#endif //UV_HTTP_HTTP_HEADER_H
