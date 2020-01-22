//
// Created by zhifan zhang on 2020/1/22.
//

#include <string>
#include "util/logger.h"
#include "http/http_header.h"
#include "http/http_url.h"



USING_NS_CC;

static void test_http_header();
static void test_http_url();

int main(int argc, char** argv)
{
    test_http_header();
    test_http_url();


    return 0;
}


static void test_http_header()
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


static void test_http_url()
{
    const char* u[] = {
            "http://www.baidu.com",
            "https://www.baidu.com:9090/r1/r23?a=b&c=d#f1",
            "https://user-account@www.baidu.com:9090/r1/r23?a=b&c=d#f1"
    };

    for (int i = 0; i < ARRAY_SIZE(u); i++) {
        http_url* url = new http_url(u[i]);

        log_d("scheam:%s, host:%s, path:%s, query:%s, is_https:%d",
                url->get_schema().c_str(),
                url->get_host().c_str(),
                url->get_path().c_str(),
                url->get_query().c_str(),
                url->is_https());
        delete url;
    }
}

