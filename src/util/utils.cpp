//
// Created by zhifan zhang on 2020/1/28.
//

#include <algorithm>

#include "util/utils.h"
#include "util/logger.h"

NS_CC_BEGIN


void utils::string_split(const std::string &s, std::vector<std::string> &res, const std::string &delimiter)
{
    std::string::size_type last_pos = s.find_first_not_of(delimiter, 0);
    std::string::size_type pos = s.find_first_of(delimiter, last_pos);

    while (std::string::npos != pos || std::string::npos != last_pos) {
        res.push_back(s.substr(last_pos, pos - last_pos));
        last_pos = s.find_first_not_of(delimiter, pos);
        pos = s.find_first_of(delimiter, last_pos);
    }
}

void utils::string_trim_left(std::string &s)
{
    const char* ws = " \t\n\r\f\v";
    s.erase(0, s.find_first_not_of(ws));
}

void utils::string_trim_right(std::string &s)
{
    const char* ws = " \t\n\r\f\v";
    s.erase(s.find_last_not_of(ws) + 1);
}

void utils::string_trim(std::string &s)
{
    string_trim_left(s);
    string_trim_right(s);
}


void utils::m_assert(const char* expr_str, bool expr, const char* file, int line, const char* msg)
{
    if (!expr) {
        const char* sim_file = strrchr(file, '/');
        if (sim_file) {
            sim_file++;
        }
        log_n("Assert Fail expr_str:%s, file:%s, line:%d, msg:%s", expr_str, sim_file ? sim_file : file, line, msg);

        abort();
    }
}

NS_CC_END
