//
// Created by zhifan zhang on 2020/1/23.
//

#include "http_test.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "http/http_request.h"
#include "http/http_form.h"
#include "data/write_buffer.h"
#include "server/http_server.h"

#include "util/utils.h"
#include "util/logger.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/aes.h"
#include "openssl/rsa.h"

NS_CC_BEGIN

http_test::http_test()
{
}


http_test::~http_test()
{

}

void http_test::run_test()
{
//    __test_http_header();
//    __test_http_url();
//    __test_http_form();
//    __test_url_encode_decode();
//    __test_utils_string();
//    __test_openssl();
//    __test_write_buffer();
//    __test_http_request();
    __test_http_server();
}


void http_test::__test_http_header()
{
    http_header* hh = new http_header();
    static const int size = 256;
    for (int i = 0; i < size; ++i) {

        char buf[64] = {0};
        if (i % 2 == 0) {
            snprintf(buf, 64, "key = %d", i);
        } else {
            snprintf(buf, 64, "value = %d", i);
        }

        hh->append_data(buf, strlen(buf));
    }

    for (int j = 0; j < size; ++j) {
        char buf[64] = {0};
        if (j % 2 == 0) {
            snprintf(buf, 64, "key = %d", j);
        } else {
            snprintf(buf, 64, "value = %d", j);
        }

        std::string val = hh->header_value_by_key(buf);
        log_d("hh val:%s", val.c_str());
    }

    hh->dump();

    delete hh;
}


void http_test::__test_http_url()
{
    const char* u[] = {
            "http://www.baidu.com",
            "https://www.baidu.com:9090/r1/r23?a=b&c=d#f1",
            "https://user-account@www.baidu.com:9090/r1/r23?a=b&c=d#f1",
            "/user/local/myfile?a=b&c=d#f3"
    };

    for (int i = 0; i < ARRAY_SIZE(u); i++) {
        http_url* url = new http_url();
        int ret = url->reset_url(u[i]);

        log_d("scheam:%s, host:%s, path:%s, query:%s, is_https:%d, ret:%d",
              url->get_schema().c_str(),
              url->get_host().c_str(),
              url->get_path().c_str(),
              url->get_query().c_str(),
              url->is_https(),
              ret);
        delete url;
    }

    http_url* url1 = new http_url();
    http_url* url2 = new http_url();

    int n1 = url1->reset_url(u[1]);
    int n2 = url2->reset_url(u[3]);
    log_d("n1:%d n2:%d", n1, n2);

    if (n2 < 0 && url2->get_full_url().at(0) == '/') {
        std::string new_url;
        new_url.append(url1->get_schema());
        new_url.append("://");
        new_url.append(url1->get_host());
        if (url1->get_port().size() > 0) {
            new_url.append(":");
            new_url.append(url1->get_port());
            new_url.append(url2->get_full_url());
        }
        log_d("new_url:%s", new_url.c_str());
    }
}

void http_test::__http_request_notify_callback(int type, const char* buf, size_t len, void* data)
{
    log_d("__http_request_notify_callback, type:%d, buf:%s", type, buf);
}


void http_test::__test_http_request()
{
    {
        const char* urls[] = {
                "http://www.kuaidi100.com/query?type=yuantong&postid=11111111111",
                "http://ip.taobao.com/service/getIpInfo.php?ip=63.223.108.42",
                "https://tcc.taobao.com/cc/json/mobile_tel_segment.htm?tel=13211020001",
                "https://suggest.taobao.com/sug?code=utf-8&q=%E6%89%8B%E6%9C%BA&callback=cb"
        };


        for (int i = 0; i < ARRAY_SIZE(urls); i++) {
            http_request* req = new http_request(urls[i]);
            req->set_notify_callback(&__http_request_notify_callback, this);
            int ret = req->do_work();
            http_request::http_result result;
            req->get_result(&result);
            log_d("req->do_work, ret = %d, result.res:%s, result.status_code:%d, result.error_code:%hu, result.connect_ip:%s",
                  ret, result.content.c_str(), result.status_code, result.error_code, result.connect_ip);
            delete req;
        }
    }

    {
        const char* url = "http://www.baidu.com/kw=k1256";
        http_request* req = new http_request(url);
        req->set_notify_callback(&__http_request_notify_callback, this);
        req->set_follow_location(1);
        int ret = req->do_work();
        log_d("req->do_work, ret = %d", ret);
        delete req;
    }



    {
        const char* url = "http://www.zhihu.com/";
        http_request* req = new http_request(url);
        req->set_keep_alive(1);
        req->set_notify_callback(&__http_request_notify_callback, this);
        int ret = req->do_work();
        http_request::http_result result;
        req->get_result(&result);
        log_d("req->do_work, ret = %d, result.res:%s, result.status_code:%d, result.error_code:%hu, result.connect_ip:%s",
                ret, result.content.c_str(), result.status_code, result.error_code, result.connect_ip);
        delete req;
    }

    {
        const char* url = "http://www.baidu.com/query?kw=q1";
        http_request* req = new http_request(url);
        req->set_follow_location(1);
        req->set_keep_alive(1);
        req->set_notify_callback(&__http_request_notify_callback, this);
        int ret = req->do_work();
        log_d("req->do_work, ret = %d", ret);
        delete req;
    }
}

void http_test::__test_url_encode_decode()
{
    {
        std::string input = "https://www.google.com.hk/search?newwindow=1&safe=strict&hl=zh-CN&source=hp&ei=q_0wXtjeIsHm-Aa-to_ACA&q=std::string case compare&oq=std::string case compare&gs_l=psy-ab.3...15391951.15399300..15399458...0.0..0.0.0.......0....1..gws-wiz.....0.QWPpRJPKHI4&ved=0ahUKEwiY4MzV8KfnAhVBM94KHT7bA4gQ4dUDCAY&uact=5";

        std::string res;
        std::string output;

        utils::url_encode(input, res);
        utils::url_decode(res, output);

        if (input.compare(output) == 0) {
            log_d("url encode & decode succ");
        }
    }

    {
        // "abc"[nm]<;qwe>=!@#$%^&*()_+-
        std::string input = "\"abc\"[nm]<;qwe>=!@#$%^&*()_+-";
        std::string res;
        std::string output;

        utils::url_encode(input, res);
        utils::url_decode(res, output);
        if (input.compare(output) == 0) {
            log_d("url encode & decode succ [%s]", res.c_str());
        }

    }

}

void http_test::__test_http_form()
{
    {
        http_form form;
        int ret = 0;
        std::string header;
        std::string body;
        std::string file="111121212j3lk1j2kl3jlkjkl";
        form.add_form_file_data(file, "test.log");

        ret = form.get_header(&header);
        log_d("get_header, ret:%d, header:%s", ret, header.c_str());
        ret = form.get_body(&body);
        log_d("get_body, ret:%d, body:%s", ret, body.c_str());

    }
}

void http_test::__test_utils_string()
{
    {
        const char* test_str = "1234\r\n12abc\r\n34klm\r\n897opq";
        std::vector<std::string> vects;
        utils::string_split(test_str, vects, "\r\n");
        for (size_t p = 0; p < vects.size(); p++) {
            log_d("vects.[%zu]:%s", p, vects[p].c_str());
        }
    }

    {
        std::string str  = " k1 k2 k3 k4 k5 \t";
        utils::string_trim(str);
        log_d("string_trim, str:%s", str.c_str());
    }
}

int http_test::__aes_decrypt(uint8_t* cipher_text, int cipher_text_len, uint8_t* key, uint8_t* iv, uint8_t* plain_text)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;


    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return -1;

    if(1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_len))
        return -1;
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len))
        return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


int http_test::__aes_encrpt(uint8_t* plain_text, int plain_text_len, uint8_t* key, uint8_t* iv, uint8_t* cipher_text)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return -1;

    if(1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plain_text_len))
        return -1;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len))
        return -1;

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


void http_test::__test_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    {
        RSA *r = NULL;
        BIGNUM *bne = NULL;
        BIO *bp_public = NULL;
        BIO *bp_private = NULL;
        int bits = 2048;

        unsigned long e = RSA_F4;
        // 1. generate rsa key
        bne = BN_new();
        int ret = BN_set_word(bne, e);
        if (ret != 1) {
            log_t("BN_set_word fail");
        }

        r = RSA_new();

        ret = RSA_generate_key_ex(r, bits, bne, NULL);
        if (ret != 1) {
            log_t("RSA_generate_key_ex fail");
        }

        // 2. save public key
        bp_public = BIO_new_file("public.pem", "w+");
        ret = PEM_write_bio_RSAPublicKey(bp_public, r);
        if (ret != 1) {
            log_t("PEM_write_bio_RSAPublicKey fail");
        }

        // 3. save private key
        bp_private = BIO_new_file("private.pem", "w+");
        ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
        if (ret != 1) {
            log_t("PEM_write_bio_RSAPrivateKey fail");
        }

        // 4. check public key encode & private key decode
        {
            int status = RSA_check_key(r);
            log_d("RSA_check_key, status:%d", status);
            char src[] = "hello";
            char out[1024] = {0};
            char dst[1024] = {0};
            int dst_len = 0;
            int out_len = 0;
            int flen = RSA_size(r);

            status = RSA_public_encrypt(strlen(src), (uint8_t *) src, (uint8_t *) dst, r, RSA_PKCS1_PADDING);
            log_d("RSA_private_encrypt, status:%d, flen:%d,  strlen(dst):%zu", status, flen, strlen(dst));
            if (status > 0) {
                dst_len = status;
            }

            status = RSA_private_decrypt(dst_len, (uint8_t *) dst, (uint8_t *) out, r, RSA_PKCS1_PADDING);
            log_d("RSA_private_decrypt, status:%d, ", status);
            if (status > 0) {
                out_len = status;
            }

            if (dst_len > 0 && out_len > 0) {
                log_d("src:%s out:%s", src, out);
            }

        }

        // 5. check private key encode & public key decode
        {
            int status = RSA_check_key(r);
            log_d("RSA_check_key, status:%d", status);
            char src[] = "hello";
            char out[1024] = {0};
            char dst[1024] = {0};
            int dst_len = 0;
            int out_len = 0;
            int flen = RSA_size(r);

            status = RSA_private_encrypt(strlen(src), (uint8_t *) src, (uint8_t *) dst, r, RSA_PKCS1_PADDING);
            log_d("RSA_private_encrypt, status:%d, flen:%d,  strlen(dst):%zu", status, flen, strlen(dst));
            if (status > 0) {
                dst_len = status;
            }

            status = RSA_public_decrypt(dst_len, (uint8_t *) dst, (uint8_t *) out, r, RSA_PKCS1_PADDING);
            log_d("RSA_private_decrypt, status:%d, ", status);
            if (status > 0) {
                out_len = status;
            }

            if (dst_len > 0 && out_len > 0) {
                log_d("src:%s out:%s", src, out);
            }

        }


        // 6. free
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        RSA_free(r);
        BN_free(bne);

    }

    // aes
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        char key_data[] = "#@()Zk";
        char iv_data[] = {0x31, 0x32, 0x33, 0x34, 0x00};
        char input_data[] = "hello";
        int ret = 0;
        uint8_t* cipher = (uint8_t*)malloc( 128 + AES_BLOCK_SIZE);
        int cipher_len = 0;

        ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, (uint8_t*) key_data, (uint8_t*) iv_data);
        log_d("EVP_EncryptInit_ex, ret:%d", ret);

        ret = EVP_EncryptUpdate(ctx, cipher, &cipher_len, (uint8_t*) input_data, strlen(input_data));
        log_d("EVP_EncryptUpdate, ret:%d, cipher_len:%d, cipher:%s", ret, cipher_len, cipher);

        int ciphertext_len = cipher_len;
        ret = EVP_EncryptFinal_ex(ctx, cipher + cipher_len, &cipher_len);
        log_d("EVP_EncryptFinal_ex, ret:%d, cipher_len:%d", ret, cipher_len);


        {
            char intput[] = "hello";
            char key_data[] = "#@()Zk";
            char iv_data[] = {0x31, 0x32, 0x33, 0x34, 0x00};
            char encode_data[1024] = {0};
            char decode_data[1024] = {0};

            int encode_len = __aes_encrpt((uint8_t*) input_data, strlen(input_data),
                    (uint8_t*) key_data, (uint8_t*) iv_data, (uint8_t*) encode_data);

            int decode_len = __aes_decrypt((uint8_t*) encode_data, encode_len,
                    (uint8_t*) key_data, (uint8_t*) iv_data, (uint8_t*) decode_data);

            log_d("decode_data:%s input:%s, encode_len:%d, decode_len:%d", decode_data, input_data, encode_len, decode_len);
        }
    }
}


void http_test::__test_write_buffer()
{
    {
        write_buffer* wb = new write_buffer();

        uint32_t len[32] = {0};
        uint8_t* mc[32] = {NULL};

        for (int i = 0; i < ARRAY_SIZE(len); i++) {
            int ret = wb->malloc_buffer(&mc[i], len[i]);
            log_d("malloc_buffer, ret:%d len:%d mc:%p", ret, len[i], mc[i]);
        }


        for (int i = 0; i < ARRAY_SIZE(len); i++) {
            int ret = wb->free_buffer(mc[i]);
            log_d("free_buffer, ret:%d", ret);
        }
        delete wb;
    }
}


void http_test::__test_http_server()
{

    http_server* server = new http_server();

    int ret = server->start_server("127.0.0.1", 8080);

    log_d("start_server, ret:%d", ret);

    while (1) {
        usleep(10 * 1000);
    }

}




class http_parser_wrapper
{
public:
    http_parser_wrapper();

    ~http_parser_wrapper();

    int parser_data(const char* in, size_t len);
public:

    static int http_data_header_field_cb(http_parser*, const char *at, size_t length);
    static int http_data_header_value_cb(http_parser*, const char *at, size_t length);
    static int http_data_header_complete(http_parser*);

    static int http_data_url_cb(http_parser*, const char *at, size_t length);
    static int http_data_message_begin(http_parser*);
    static int http_data_message_complete(http_parser*);
    static int http_data_chunk_complete(http_parser*);
    static int http_data_chunk_header(http_parser*);

private:
    http_parser parser;
    http_parser_settings settings;

};

    http_parser_wrapper::http_parser_wrapper()
    {
        http_parser_init(&parser, HTTP_REQUEST);
        memset(&settings, 0, sizeof(http_parser_settings));

        settings.on_header_field = &http_data_header_field_cb;
        settings.on_header_value = &http_data_header_value_cb;
        settings.on_url = &http_data_url_cb;
        settings.on_message_begin = &http_data_message_begin;
        settings.on_message_complete = &http_data_message_complete;
        settings.on_chunk_complete = &http_data_chunk_complete;
        settings.on_chunk_header = &http_data_chunk_header;
        settings.on_headers_complete = &http_data_header_complete;
        settings.on_message_complete = &http_data_header_complete;
    }


    http_parser_wrapper::~http_parser_wrapper()
    {

    }

    int http_parser_wrapper::parser_data(const char *in, size_t len)
    {
        int np = http_parser_execute(&parser, &settings, in, len);
        return np;
    }

    int http_parser_wrapper::http_data_header_field_cb(http_parser*, const char *at, size_t length)
    {
        log_d("http_data_header_field_cb");
        char buf[URL_MAX_LEN] = {0};
        if (length > 0 && length < URL_MAX_LEN) {
            memcpy(buf, at, length);
            log_d("http_data_header_field_cb, buf:%s", buf);
        }
        return 0;
    }

    int http_parser_wrapper::http_data_header_value_cb(http_parser*, const char *at, size_t length)
    {
        log_d("http_data_header_value_cb");
        char buf[URL_MAX_LEN] = {0};
        if (length > 0 && length < URL_MAX_LEN) {
            memcpy(buf, at, length);
            log_d("http_data_header_value_cb, buf:%s", buf);
        }
        return 0;
    }

    int http_parser_wrapper::http_data_header_complete(http_parser*)
    {
        log_d("http_data_header_complete");
        return 0;
    }

    int http_parser_wrapper::http_data_url_cb(http_parser*, const char *at, size_t length)
    {
        log_d("http_data_url_cb");

        char buf[URL_MAX_LEN] = {0};
        if (length > 0 && length < URL_MAX_LEN) {
            memcpy(buf, at, length);
            log_d("http_data_url_cb, buf:%s", buf);
        }
        return 0;
    }


    int http_parser_wrapper::http_data_message_begin(http_parser*)
    {
        log_d("http_data_message_begin");
        return 0;
    }


    int http_parser_wrapper::http_data_message_complete(http_parser*)
    {
        log_d("http_data_message_complete");
        return 0;
    }

    int http_parser_wrapper::http_data_chunk_complete(http_parser*)
    {
        log_d("http_data_chunk_complete");
        return 0;
    }

    int http_parser_wrapper::http_data_chunk_header(http_parser*)
    {
        log_d("http_data_chunk_header");
        return 0;
    }


NS_CC_END


