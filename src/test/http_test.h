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

    void __test_http_form();

    void __test_url_encode_decode();

    void __test_utils_string();

    void __test_openssl();

    void __test_write_buffer();

private:
    static void __http_request_notify_callback(int type, const char* buf, size_t len, void* data);

};

NS_CC_END


#endif //UV_HTTP_HTTP_TEST_H
