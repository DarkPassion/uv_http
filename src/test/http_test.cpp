//
// Created by zhifan zhang on 2020/1/23.
//

#include "http_test.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "http/http_request.h"
#include "http/http_form.h"
#include "util/utils.h"
#include "util/logger.h"

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
    __test_url_encode_decode();
//    __test_http_request();
//    __test_utils_string();
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
            "https://user-account@www.baidu.com:9090/r1/r23?a=b&c=d#f1"
    };

    for (int i = 0; i < ARRAY_SIZE(u); i++) {
        http_url* url = new http_url();
        url->reset_url(u[i]);

        log_d("scheam:%s, host:%s, path:%s, query:%s, is_https:%d",
              url->get_schema().c_str(),
              url->get_host().c_str(),
              url->get_path().c_str(),
              url->get_query().c_str(),
              url->is_https());
        delete url;
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

NS_CC_END


