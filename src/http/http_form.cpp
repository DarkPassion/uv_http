//
// Created by zhifan zhang on 2020/1/29.
//

#include "http/http_form.h"
#include "util/logger.h"

#include <sstream>

NS_CC_BEGIN

static const char* FORM_BOUNDARY_STR = "------------------------53196fb280119023";

http_form::http_form()
{
    _header.clear();
    _body.clear();
    _index = 0;
}

http_form::~http_form()
{
    _header.clear();
    _body.clear();
    log_d("http_form dctor");
}


int http_form::add_form_file_data(std::string &file, const char* name)
{
    reset();

    std::string header;
    header.append("Content-Type: multipart/form-data; boundary=");
    header.append(FORM_BOUNDARY_STR);
    header.append("\r\n");
    _header.append(header);


    std::ostringstream body_ss;
    body_ss << "--" << FORM_BOUNDARY_STR << "\r\n";
    body_ss << _generate_file_form();
    body_ss << "filename=" << name << "\r\n";
    body_ss << "Content-Type: application/octet-stream\r\n\r\n";

    body_ss << file << "\r\n\r\n";
    body_ss << "--" << FORM_BOUNDARY_STR << "--";

    _body.append(body_ss.str());
    return 0;
}

int http_form::get_body(std::string *body)
{
    if (body == NULL) {
        log_t("get_body body = null");
        return -1;
    }

    body->append(_body);
    return 0;
}

int http_form::get_header(std::string *header)
{
    if (header == NULL) {
        log_t("get_header header = null");
        return -1;
    }

    header->append(_header);
    return 0;
}


int http_form::reset()
{
    _header.clear();
    _body.clear();
    return 0;
}


std::string http_form::_generate_file_form()
{
    std::string ret;
    char buf[64] = {0};
    snprintf(buf, ARRAY_SIZE(buf), "input_file_%d", _index++);
    ret.append("Content-Disposition: form-data; name=\"");
    ret.append(buf);
    ret.append("\"; ");
    return ret;
}

NS_CC_END


