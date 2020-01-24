//
// Created by zhifan zhang on 2020/1/23.
//

#include "http_test.h"
#include "http/http_header.h"
#include "http/http_url.h"
#include "http/http_request.h"
#include "util/logger.h"

NS_CC_BEGIN

    class data_url
    {
    public:
        data_url();

        ~data_url();

        void parse(const std::string& url_s);

    public:
        std::string protocol_, host_, path_, query_, port_, full_url_;

    private:
    DISALLOW_COPY_AND_ASSIGN(data_url);

    };

    data_url::data_url()
    {

    }


    data_url::~data_url()
    {

    }


    void data_url::parse(const std::string& url_s)
    {
        if (url_s.length() == 0)
            return ;

        if (full_url_.compare(url_s) != 0) {
            full_url_ = url_s;
        }
        std::string::const_iterator uriEnd = url_s.end();

        // get query start
        std::string::const_iterator queryStart = std::find(url_s.begin(), uriEnd, '?');

        // protocol
        std::string::const_iterator protocolStart = url_s.begin();
        std::string::const_iterator protocolEnd = std::find(protocolStart, uriEnd, ':');            //"://");

        if (protocolEnd != uriEnd)
        {
            std::string prot = &*(protocolEnd);
            if ((prot.length() > 3) && (prot.substr(0, 3) == "://"))
            {
                protocol_ = std::string(protocolStart, protocolEnd);
                protocolEnd += 3;   //      ://
            } else {
                protocolEnd = url_s.begin();  // no protocol
            }
        } else {
            protocolEnd = url_s.begin();  // no protocol
        }

        // host
        std::string::const_iterator hostStart = protocolEnd;
        std::string::const_iterator pathStart = std::find(hostStart, uriEnd, '/');  // get pathStart

        std::string::const_iterator hostEnd = std::find(protocolEnd,
                                                        (pathStart != uriEnd) ? pathStart : queryStart,
                                                        ':');  // check for port

        host_ = std::string(hostStart, hostEnd);

        // port
        if ((hostEnd != uriEnd) && ((&*(hostEnd))[0] == ':'))  // we have a port
        {
            hostEnd++;
            std::string::const_iterator  portEnd = (pathStart != uriEnd) ? pathStart : queryStart;
            port_ = std::string(hostEnd, portEnd);
        }

        // path
        if (pathStart != uriEnd) {
            path_ = std::string(pathStart, queryStart);
        }

        // query
        if (queryStart != uriEnd) {
            query_ = std::string(queryStart, url_s.end());
        }


    }

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
    const char* url = "http://www.baidu.com/kw?str=1234";
    http_request* req = new http_request(url);
    int ret = req->do_work();
    log_d("req->do_work, ret = %d", ret);
    delete req;
}


NS_CC_END


