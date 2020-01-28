//
// Created by zhifan zhang on 2020/1/25.
//

#ifndef UV_HTTP_HTTP_CHUNK_H
#define UV_HTTP_HTTP_CHUNK_H


#include "util/define.h"

NS_CC_BEGIN

class http_chunk {

public:
    http_chunk();

    ~http_chunk();

    int input_data(const char* data, int len);

    int is_eof();

    // [chunk size] [\r\n] [chunk data] [\r\n] [chunk size] [\r\n] [chunk data] [\r\n] [chunk size = 0] [\r\n] [\r\n]
    enum {
        CHUNK_HEADER_LENGTH = 1,
        CHUNK_BODY,
    };
private:
    int __find_chunk_body_pos(const char* data, int len);

    int __find_transfer_encode(const char* data, int len);

    int __input_chunk_header(const char* data, int len);

    int __input_chunk_body(const char* data, int len);
private:
    uint32_t    _header_length;
    uint32_t    _body_pos;
    uint8_t     _is_eof;
    uint8_t     _is_chunked_encode;
    uint8_t     _body_begin;
    uint8_t     _state;
};



NS_CC_END


#endif //UV_HTTP_HTTP_CHUNK_H
