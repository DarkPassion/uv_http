//
// Created by zhifan zhang on 2020/2/7.
//

#include <string.h>

#include "data/send_data.h"
#include "util/utils.h"
#include "util/logger.h"

#define DEFAULT_QUEUE_NUM     (2)

NS_CC_BEGIN

send_data::send_data()
{
    memset(this, 0, sizeof(send_data));
}

send_data::~send_data()
{
    if (buff_alloc) {
        for (int i = 0; i < nbuf; i++) {
            if (buf[i].base) free(buf[i].base);

            buf[i].base = NULL;
            buf[i].len = 0;
        }
    }

    log_d("send_data dctor");
}





send_queue::send_queue()
{
    _size = 0;
    _used = 0;
    _queue = NULL;
    _expand_size(DEFAULT_QUEUE_NUM);
}

send_queue::~send_queue()
{
    for (int i = 0; i < _size; i++) {
        send_data* sed = _queue[i];
        delete sed;
    }

    free(_queue);
    _queue = NULL;

    log_d("send_queue dctor, size:%d used:%d", _size, _used);
}

send_data * send_queue::new_data()
{
    send_data* data = NULL;
    if (_used + 1 >= _size) {
        int ns = _size * 2;
        _expand_size(ns);
    }

    for (int i = 0; i < _size; i++) {
        if (_queue[i]->flag == send_data::IDLE) {
            _queue[i]->flag = send_data::IN_USE;
            data = _queue[i];
            _used++;
            break;
        }
    }
    log_d("send_queue new_data, size:%d used:%d", _size, _used);

    M_ASSERT(data != NULL, "new_data fail");
    if (data != NULL) {
        memset(data, 0, sizeof(send_data));
    }
    return data;
}

void send_queue::delete_data(send_data* data)
{
    uint8_t is_find = 0;
    for (int i = 0; i < _size; i++) {
        if (_queue[i]->flag == send_data::IN_USE && _queue[i] == data) {
            _queue[i]->flag = send_data::IDLE;
            _used--;
            is_find = 1;
            break;
        }
    }
    if (is_find == 0) {
        log_d("send_queue::delete_data fail");
    }
    log_d("send_queue delete_data, size:%d used:%d", _size, _used);
}

int send_queue::_expand_size(int size)
{
    void* p = _queue;
    if (p != NULL) {
        _queue = (send_data**) realloc(p, size * sizeof(send_data*));
    } else {
        _queue = (send_data**) malloc(size * sizeof(send_data**));
    }

    for (int i = _size; i < size; ++i) {
        _queue[i] = (send_data*) malloc(sizeof(send_data));
        memset(_queue[i], 0, sizeof(send_data));
    }

    _size = size;

    log_d("send_queue _expand_size, size:%d used:%d", _size, _used);
    return 0;
}

NS_CC_END


