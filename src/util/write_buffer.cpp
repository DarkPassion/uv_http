//
// Created by zhifan zhang on 2020/1/31.
//

#include "util/write_buffer.h"
#include "util/logger.h"


NS_CC_BEGIN

#define DEFAULT_NUM             (3)
#define DEFAULT_BUFF_LEN        (1024*4)

write_buffer::write_buffer()
{
    for (int i = 0; i < DEFAULT_NUM; i++) {
        private_data* pd = new private_data();
        pd->flags = DATA_FLAG_IDEL;
        pd->data_len = DEFAULT_BUFF_LEN;
        pd->data = (uint8_t*) malloc(pd->data_len);
        memset(pd->data, 0, pd->data_len);

        _queue.push_back(pd);
    }
    _used_num = 0;
}


write_buffer::~write_buffer()
{
    M_ASSERT(_used_num == 0, "_used_num should eq 0");

    for (int i = 0; i < _queue.size(); i++) {
        private_data* pd = _queue[i];
        free(pd->data);
        delete pd;
    }

    _queue.clear();
    log_d("write_buffer dctor");
}


int write_buffer::malloc_buffer(uint8_t **data, uint32_t &len)
{
    if (data == NULL) {
        log_t("malloc_buffer data = null");
        return -1;
    }
    if (_used_num >= _queue.size()) {
        int ns = _queue.size() * 2;

        for (int i = 0; i < ns; i++) {
            private_data* pd = new private_data();
            pd->flags = DATA_FLAG_IDEL;
            pd->data_len = DEFAULT_BUFF_LEN;
            pd->data = (uint8_t*) malloc(pd->data_len);
            memset(pd->data, 0, pd->data_len);
            _queue.push_back(pd);
        }
        log_d("malloc_buffer, new_size:%zu", _queue.size());
    }

    int ret = -1;
    for (size_t i = 0; i < _queue.size(); ++i) {
        private_data* pd = _queue[i];
        if (pd->flags == DATA_FLAG_IDEL) {

            pd->flags = DATA_FLAG_USED;
            *data = pd->data;
            len = pd->data_len;
            ret = 0;
            _used_num++;
            break;
        }
    }
    return ret;
}

int write_buffer::free_buffer(uint8_t *data)
{
    int ret = -1;
    for (size_t i = 0; i < _queue.size(); ++i) {
        private_data* pd = _queue[i];
        if (pd->flags == DATA_FLAG_USED && pd->data == data) {
            pd->flags = DATA_FLAG_IDEL;
            ret = 0;
            _used_num--;
            log_d("free_buffer, use_num:%d", _used_num);
            break;
        }
    }
    return ret;
}


NS_CC_END


