//
// Created by zhifan zhang on 2020/1/22.
//


#ifndef UV_HTTP_UTIL_LOGGER_H
#define UV_HTTP_UTIL_LOGGER_H

#include "define.h"

NS_CC_BEGIN


#define log_d(...)      logger::get()->write_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_t(...)      logger::get()->write_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_n(...)      logger::get()->write_log(LOG_NOTICE, __FILE__, __LINE__, __VA_ARGS__)
#define log_w(...)      logger::get()->write_log(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)

enum {
    LOG_DEBUG   = 1 << 4,
    LOG_TRACE   = 1 << 3,
    LOG_NOTICE  = 1 << 2,
    LOG_WARNING = 1 << 1,
};
class logger {
public:
    static logger* get();

    void write_log(int level, const char* file, int line, const char* format, ...);

private:
    logger();

    ~logger();

private:
    static logger* my_logger;
    int     my_level;
};



NS_CC_END

#endif

