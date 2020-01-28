//
// Created by zhifan zhang on 2020/1/25.
//

#include "http/http_chunk.h"
#include "util/logger.h"
#include "util/utils.h"
#include <string.h>
#include <string>

NS_CC_BEGIN

#define HTTP_CR                  '\r'
#define HTTP_LF                  '\n'

#define HTTP_TRANSFER_ENCODEING     "Transfer-Encoding"
#define HTTP_TRANSFER_CHUNKED       "chunked"


http_chunk::http_chunk()
{
    _is_eof = 0;
    _header_length = 0;
    _body_pos = 0;
    _body_begin = 0;
    _is_chunked_encode = 0;
    _state = CHUNK_HEADER_LENGTH;
}


http_chunk::~http_chunk()
{
    _is_eof = 0;
    _header_length = 0;
    _body_pos = 0;
    _body_begin = 0;
}


int http_chunk::input_data(const char *data, int len)
{
    int ret = -1;
    if (_body_begin == 0) {
        ret = __find_transfer_encode(data, len);
        log_d("__find_transfer_encode, ret:%d", ret);
        ret = __find_chunk_body_pos(data, len);
        if (ret < 0) {
            log_t("__find_chunk_body_pos fail");
            return -1;
        }
    }

    if (_body_begin == 0 || _is_chunked_encode == 0) {
        log_d("input_data body_begin no");
        return 0;
    }

    int pos = ret > 0 ? ret : 0;
    while (pos <= len) {
        M_ASSERT(len >= pos, "len >= pos fail");
        int ns = 0;
        if (len == pos) {
            log_d("input_data len=pos: %d", len);
            break;
        }

        if (_is_eof) {
            log_d("input_data eof");
            break;
        }
        if (_state == CHUNK_HEADER_LENGTH) {
            ns = __input_chunk_header(data + pos, len - pos);
            if (ns < 0) {
                M_ASSERT(false, "__input_chunk_header_length fail");
                break;
            }
            pos += ns;
        } else if (_state == CHUNK_BODY) {
            ns = __input_chunk_body(data + pos, len - pos);
            if (ns < 0) {
                M_ASSERT(false, "__input_chunk_body fail");
                break;
            }
            pos += ns;
        } else {
            log_t("input_data error state _state ");
            break;
        }
    }

    return 0;
}


int http_chunk::is_eof()
{
    return _is_eof;
}

int http_chunk::__find_chunk_body_pos(const char* data, int len)
{
    if (data == NULL || len <= 0) {
        log_t("__find_chunk_body_pos data = null or len <= 0");
        return -1;
    }

    for (int i = 0; i < len - 3; i++) {
        if (data[i + 0] == HTTP_CR && data[i + 1] == HTTP_LF && data[i + 2] == HTTP_CR && data[i + 3] == HTTP_LF) {
            _body_begin = 1;
            return i + 4;
        }
    }
    return 0;
}

int http_chunk::__find_transfer_encode(const char* data, int len)
{
    if (_body_begin) {
        log_t("__find_transfer_encode http body already begin");
        return -1;
    }

    // find first [\r\n]
    int apos = 0;
    for (int i = 0; i < len - 1; i++) {
        if (data[i+0] == HTTP_CR && data[i+1] == HTTP_LF) {
            apos = i+2;
            break;
        }
    }

    std::string line;
    for (int i = apos; i < len - 1; i++) {
        if (data[i+0] == HTTP_CR && data[i+1] == HTTP_LF) {

            if (i == apos) {
                log_d("__find_transfer_encode i = apos = %d", i);
                // [\r\n\r\n] http header end,
                break;
            }
            line.clear();
            line.append(data + apos, i - apos);
            log_d("__find_transfer_encode line:%s", line.c_str());
            apos = i + 2;

            std::vector<std::string> vects;
            utils::string_split(line, vects, ":");
            if (vects.size() == 2) {
                std::string head_k = vects[0];
                std::string head_v = vects[1];

                utils::string_trim(head_k);
                utils::string_trim(head_v);

                if (head_k.compare(HTTP_TRANSFER_ENCODEING) == 0 && head_v.compare(HTTP_TRANSFER_CHUNKED) == 0) {
                    log_d("http transfer-encodeing: chunked");
                    _is_chunked_encode = 0x01;
                }
            }
        }
    }

    return 0;
}


    int http_chunk::__input_chunk_header(const char* data, int len)
{
    if (_state != CHUNK_HEADER_LENGTH) {
        log_t("__input_chunk_header_length state error");
        return -1;
    }

    if (data == NULL || len <= 0) {
        log_t("__input_chunk_header_length data = null");
        return -1;
    }


    int pos = 0;
    char chunk_size_buf[12] = {0};
    uint32_t chunk_size = 0;
    for (int i = 0; i < len - 2; i++) {
        if (data[i + 0] == HTTP_CR && data[i + 1] == HTTP_LF) {
            pos = i;
            break;
        }
    }
    log_d("__input_chunk_header_length pos:%d", pos);
    if (pos >= ARRAY_SIZE(chunk_size_buf)) {
        M_ASSERT(false, "pos > ARRAY_SIZE(chunk_size_buf)");
    }

    if (pos > 0 && pos < len) {
        memcpy(chunk_size_buf, data, pos);
        chunk_size =  (uint32_t) std::strtol(chunk_size_buf, NULL, 16);
        _header_length = chunk_size;
        _body_pos = 0;
        _state = CHUNK_BODY;
        log_t("chunk_size:%u, chunk_size_buff:%s", chunk_size, chunk_size_buf);
    } else {
        log_t("__input_chunk_header_length pos:%d", pos);
        return -1;
    }
    return pos + 2;
}

int http_chunk::__input_chunk_body(const char* data, int len)
{
    if (_header_length == 0 && _body_pos == 0 && len == 2 && data[0] == HTTP_CR && data[1] == HTTP_LF) {
        // last chunk size
        _is_eof = 0x01;
        log_t("__input_chunk_body last chunk size");
        return 0;
    }
    int left_len = _header_length - _body_pos;
    log_d("__input_chunk_body, data[0]:%c, data[1]:%c", data[0], data[1]);
    log_d("__input_chunk_body, left_len:%d, body_pos:%d, header_length:%d, len:%d", left_len, _body_pos, _header_length, len);
    if (len - 2 >= left_len) {
        _body_pos = 0;
        _header_length = 0;
        _state = CHUNK_HEADER_LENGTH;

        int pos = left_len;

        log_d("cr:%x lf:%x, %x, %x, %x, %x", HTTP_CR, HTTP_LF, data[pos + 0], data[pos + 1], data[pos + 2], data[pos + 3]);
        if (data[pos + 0] == HTTP_CR && data[pos + 1] == HTTP_LF) {
            log_t("__input_chunk_body pos:%x %x", data[pos + 0], data[pos + 1]);
        } else {
            M_ASSERT(false, "__input_chunk_body encode fail");
        }
        return left_len + 2;
    } else {
        _body_pos += len;
        log_t("__input_chunk_body len:%d", len);
        return len;
    }
}




NS_CC_END
