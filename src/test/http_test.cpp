//
// Created by zhifan zhang on 2020/1/23.
//

#include "http_test.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "http/http_request.h"
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
    __test_http_request();
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

        const char* val = hh->header_value_by_key(buf);
        log_d("hh val:%s", val == NULL ? "null" : val);
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


void http_test::__test_http_request()
{
    M_ASSERT(false, "expr false");
    const char* url = "http://www.baidu.com/kw=k1256";
    http_request* req = new http_request(url);
    int ret = req->do_work();
    log_d("req->do_work, ret = %d", ret);
    delete req;
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


