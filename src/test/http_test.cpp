//
// Created by zhifan zhang on 2020/1/23.
//

#include "http_test.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "http/http_request.h"
#include "http/http_form.h"
#include "util/write_buffer.h"

#include "util/utils.h"
#include "util/logger.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"

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
    __test_http_request();
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
        log_d("req->do_work, ret = %d", ret);
        delete req;
    }

    {
        const char* url = "http://www.baidu.com/kw=k1256";
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

struct ssl_trans
{
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    BIO* read_bio;
    BIO* write_bio;
};

static void ssl_trans_on_event(ssl_trans*);
static void ssl_trans_handle_error(ssl_trans*, int);
static void ssl_trans_flush_read_bio(ssl_trans*);

void http_test::__test_openssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    ssl_trans* session = new ssl_trans();
    memset(session, 0, sizeof(ssl_trans));

    session->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(session->ssl_ctx, SSL_OP_NO_SSLv2);
    session->ssl = SSL_new(session->ssl_ctx);
    session->read_bio = BIO_new(BIO_s_mem());
    session->write_bio = BIO_new(BIO_s_mem());
    SSL_set_bio(session->ssl, session->read_bio, session->write_bio);

    SSL_set_connect_state(session->ssl);

    int ret = SSL_do_handshake(session->ssl);
    log_d("SSL_do_handshake, ret:%d", ret);

    if(!SSL_is_init_finished(session->ssl)) {
        ret = SSL_connect(session->ssl);
        if (ret < 0) {
            ssl_trans_handle_error(session, ret);
        }
    }

    SSL_CTX_free(session->ssl_ctx);
    SSL_free(session->ssl);
//    BIO_free(session->write_bio);
//    BIO_free(session->read_bio);


    delete session;

}

static void ssl_trans_handle_error(ssl_trans* session, int result)
{
    log_d("ssl_trans_handle_error, result:%d", result);
    int error = SSL_get_error(session->ssl, result);
    if(error == SSL_ERROR_WANT_READ) { // wants to read from bio
        ssl_trans_flush_read_bio(session);
    }
}

static void ssl_trans_flush_read_bio(ssl_trans* session)
{
    log_d("ssl_trans_flush_read_bio");

    char buf[1024*4];
    int bytes_read = 0;
    while((bytes_read = BIO_read(session->write_bio, buf, sizeof(buf))) > 0) {
        log_d("ssl_trans_flush_read_bio, bytes_read:%d, buf:%s", bytes_read, buf);

//        write_to_socket(c, buf, bytes_read);
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



NS_CC_END


