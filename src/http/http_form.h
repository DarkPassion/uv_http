//
// Created by zhifan zhang on 2020/1/29.
//

#ifndef UV_HTTP_HTTP_FORM_H
#define UV_HTTP_HTTP_FORM_H

#include <string>

#include "util/define.h"

NS_CC_BEGIN

class http_form {

public:
    http_form();

    ~http_form();

    int add_form_file_data(std::string& file, const char* name);

    int reset();

    int get_header(std::string* header);

    int get_body(std::string* body);

private:
    std::string _generate_file_form();

private:
    std::string     _header;
    std::string     _body;
    uint16_t        _index;
};

NS_CC_END


#endif //UV_HTTP_HTTP_FORM_H
