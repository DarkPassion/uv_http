//
// Created by zhifan zhang on 2020/2/7.
//

#ifndef UV_HTTP_HTTP_CODE_H
#define UV_HTTP_HTTP_CODE_H

#include "util/define.h"

NS_CC_BEGIN

    enum error_code {
        ERROR_SUCC = 0,
        ERROR_DNS_RESOLVE = 1,
        ERROR_CONNECT = 2,
        ERROR_SOCKET_READ = 3,
        ERROR_SOCKET_WRITE = 4,
        ERROR_TIMEOUT = 5,
        ERROR_INTERNAL = 6,
    };

NS_CC_END

#endif //UV_HTTP_HTTP_CODE_H
