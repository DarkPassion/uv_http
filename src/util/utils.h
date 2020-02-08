//
// Created by zhifan zhang on 2020/1/28.
//

#ifndef UV_HTTP_UTILS_H
#define UV_HTTP_UTILS_H


#include "define.h"
#include <string>
#include <vector>


NS_CC_BEGIN

class utils {

public:
    static void string_split(const std::string& s, std::vector<std::string>& res, const std::string& delimiter);

    static void string_trim_left(std::string& s);

    static void string_trim_right(std::string& s);

    static void string_trim(std::string& s);

    static bool string_start_with(const std::string& s, const std::string& p);

    static bool string_end_with(const std::string& s, const std::string& p);

    static void string_upper(std::string& s);

    static void string_lower(std::string& s);

    static std::string string_format(const char* fmt, ...);

    static void url_encode(std::string& s, std::string& res);

    static void url_decode(std::string& s, std::string& res);

    //  the gzip compress level -1 = default, 0 = no compression, 1= worst/fastest compression, 9 = best/slowest compression
    static int gzip_encode(std::string& s, std::string& res, int level = -1);

    static int gzip_encode(const char* in, int inlen, std::string& res, int level = -1);

    static int gzip_decode(std::string& s, std::string& res);

    static int string_html_encode(std::string& s);

    static uint64_t get_timestamp();

    static void m_assert(const char* expr_str, bool expr, const char* file, int line, const char* msg);
};

NS_CC_END

#endif //UV_HTTP_UTILS_H
