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
    enum {
        MAX_SEND_NUM = 8,
    };

    enum {
        IDLE = 0,
        IN_USE,
    };

    uv_write_t  write;
    uv_buf_t    buf[MAX_SEND_NUM];
    uint16_t    nbuf;
    uint8_t     buff_alloc;
    uint8_t     flag;
    void*       data;

    send_data();

    ~send_data();
};


class send_queue
{
public:
    send_queue();

    ~send_queue();

    send_data* new_data();

    void delete_data(send_data*);

private:
    int _expand_size(int size);

private:
    send_data** _queue;
    int         _used;
    int         _size;
};



NS_CC_END


#endif //UV_HTTP_SEND_DATA_H
