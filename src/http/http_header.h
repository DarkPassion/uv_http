//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_HTTP_HEADER_H
#define UV_HTTP_HTTP_HEADER_H

#include "util/define.h"
#include <string>


NS_CC_BEGIN

class http_header {
public:
    http_header();

    ~http_header();

    // request
    int add_data(const char* key, const char* val);

    // response
    int append_data(const char* data, int len);

    std::string get_value_by_key(const char* key);

    int get_content_length();

    bool is_chunked_encode();

    void dump();

    int write_to_buff(char* buf, int len);

private:
    struct hd_data_t;

    int _expand_size(int size);

    hd_data_t* _find_node(const char* key);

    enum {
        kMaxLen = 256,
    };

    enum {
        kIndexName = 0,
        kIndexValue,
    };


    struct hd_data_t
    {
        char name[kMaxLen];
        char value[kMaxLen];
    };


private:
    uint8_t     state;
    int         headers_pos;
    int         headers_len;
    struct hd_data_t** headers;
};

NS_CC_END

#endif //UV_HTTP_HTTP_HEADER_H
