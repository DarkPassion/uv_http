//
// Created by zhifan zhang on 2020/1/23.
//

#ifndef UV_HTTP_HTTP_TEST_H
#define UV_HTTP_HTTP_TEST_H

#include "util/define.h"

NS_CC_BEGIN

class http_message;
class http_channel;

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

    void __test_http_server();


    int __aes_encrpt(uint8_t* plain_text, int plain_text_len, uint8_t* key, uint8_t* iv, uint8_t* cipher_text);

    int __aes_decrypt(uint8_t* cipher_text, int cipher_text_len, uint8_t* key, uint8_t* iv, uint8_t* plain_text);


private:
    static void __http_request_notify_callback(int type, const char* buf, size_t len, void* data);

    static int __http_server_handler_service(http_message* msg, http_channel* channel, void* user);

};

NS_CC_END


#endif //UV_HTTP_HTTP_TEST_H
