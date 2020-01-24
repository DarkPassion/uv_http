//
// Created by zhifan zhang on 2020/1/23.
//

#ifndef UV_HTTP_HTTP_TEST_H
#define UV_HTTP_HTTP_TEST_H

#include "util/define.h"

NS_CC_BEGIN

class http_test {

public:
    http_test();

    ~http_test();

    void run_test();


private:
    void __test_http_header();

    void __test_http_url();

    void __test_http_request();

};

NS_CC_END


#endif //UV_HTTP_HTTP_TEST_H
