//
// Created by zhifan zhang on 2020/2/7.
//

#ifndef UV_HTTP_SEND_DATA_H
#define UV_HTTP_SEND_DATA_H


#ifdef __cplusplus
extern "C" {
#endif

#include "uv.h"

#ifdef __cplusplus
}
#endif

#include "util/define.h"


NS_CC_BEGIN


struct send_data {
    uv_write_t  write;
    uv_buf_t    buf;
    uint8_t     buff_alloc;
    void*       data;
};


void send_data_destory(send_data** s);




NS_CC_END


#endif //UV_HTTP_SEND_DATA_H
