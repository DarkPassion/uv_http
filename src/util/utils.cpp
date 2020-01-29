//
// Created by zhifan zhang on 2020/1/28.
//

#include <algorithm>

#include "util/utils.h"
#include "util/logger.h"

NS_CC_BEGIN

    static char __char_to_int(char ch);
    static char __str_to_bin(char* s);

    static char __char_to_int(char ch)
    {
        if (ch >= '0' && ch <= '9')
        {
            return (char)(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f')
        {
            return (char)(ch - 'a' + 10);
        }
        if (ch >= 'A' && ch <= 'F')
        {
            return (char)(ch - 'A' + 10);
        }
        return -1;
    }


    static char __str_to_bin(char* p)
    {
        char buffer[2] = {0};
        char ch;
        buffer[0] = __char_to_int(p[0]);    // make the B to 11 -- 00001011
        buffer[1] = __char_to_int(p[1]);    // make the 0 to 0 -- 00000000
        ch = (buffer[0] << 4) | buffer[1];      // to change the BO to 10110000
        return ch;
    }

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

void utils::url_encode(std::string& s, std::string &res)
{
    uint8_t* pdata = (unsigned char*)s.c_str();
    char alnum[2] = {0};
    char other[4] = {0};
    for (size_t i = 0; i < s.length(); i++)
    {
        if (isalnum((uint8_t)s[i]))
        {
            snprintf(alnum, sizeof(alnum), "%c", s[i]);
            res.append(alnum);
        }
        else if (isspace((uint8_t)s[i]))
        {
            res.append("+");
        }
        else
        {
            snprintf(other, sizeof(other), "%%%X%X", pdata[i] >> 4, pdata[i] % 16);
            res.append(other);
        }
    }
}

void utils::url_decode(std::string &s, std::string &res)
{
    char sz_temp[2] = {0};
    size_t i = 0;
    while (i < s.length())
    {
        if (s[i] == '%')
        {
            sz_temp[0] = s[i + 1];
            sz_temp[1] = s[i + 2];
            res += __str_to_bin(sz_temp);
            i = i + 3;
        }
        else if (s[i] == '+')
        {
            res += ' ';
            i++;
        }
        else
        {
            res += s[i];
            i++;
        }
    }
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
