#include "util/logger.h"

#include <string.h>
#include <stdarg.h>


NS_CC_BEGIN

static const char* log_tag = "uv_http";

logger* logger::my_logger = NULL;

logger::logger()
{
    my_level = LOG_DEBUG;
}

logger::~logger()
{

}

logger * logger::get()
{
    if (my_logger == NULL) {
        my_logger = new logger();
    }

    return my_logger;
}

void logger::write_log(int level, const char *file, int line, const char *format, ...)
{
    if (level > my_level) {
        return;
    }

    const char* sim_file = strrchr(file, '/');
    if (sim_file) {
        sim_file++;
    }

    char log[1024]  = {0};
    va_list args;
    va_start(args, format);
    vsnprintf(log, sizeof(log), format, args);
    va_end(args);
    log[sizeof(log) -  1] = 0;


    printf( "%s file:%s line:%d %s\n", log_tag, sim_file ? sim_file : file, line, log);
}

NS_CC_END


