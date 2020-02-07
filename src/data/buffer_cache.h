//
// Created by zhifan zhang on 2020/1/31.
//

#ifndef UV_HTTP_BUFFER_CACHE_H
#define UV_HTTP_BUFFER_CACHE_H


#include <string>
#include <vector>
#include <stdint.h>
#include "util/define.h"

NS_CC_BEGIN

class buffer_cache {

public:
    buffer_cache();

    ~buffer_cache();


    int malloc_buffer(uint8_t** data, uint32_t& len);

    int free_buffer(uint8_t* data);

private:
    enum {
        DATA_FLAG_IDEL = 0,
        DATA_FLAG_USED,
    };

    struct private_data
    {
        uint8_t*    data;
        uint32_t    data_len;
        uint8_t     flags;
    };

    std::vector<private_data*>  _queue;
    uint32_t                    _used_num;
};


NS_CC_END

#endif //UV_HTTP_BUFFER_CACHE_H
