//
// Created by zhifan zhang on 2020/2/7.
//

#include <string>
#include "util/utils.h"
#include "data/http_code.h"


NS_CC_BEGIN


#define MAX_STATUS_NUM  (1024)

struct http_status_msg
{
    const char* msg[MAX_STATUS_NUM];
    const char* fname[MAX_STATUS_NUM];
};

struct http_content_type_msg
{
    const char* ext[MAX_STATUS_NUM];
    const char* type[MAX_STATUS_NUM];
};

static http_status_msg* __msg = NULL;
static http_content_type_msg* __type = NULL;



/* Status Codes */
#define HTTP_STATUS_MAP(XX)                                                 \
  XX(100, CONTINUE,                        Continue)                        \
  XX(101, SWITCHING_PROTOCOLS,             Switching Protocols)             \
  XX(102, PROCESSING,                      Processing)                      \
  XX(200, OK,                              OK)                              \
  XX(201, CREATED,                         Created)                         \
  XX(202, ACCEPTED,                        Accepted)                        \
  XX(203, NON_AUTHORITATIVE_INFORMATION,   Non-Authoritative Information)   \
  XX(204, NO_CONTENT,                      No Content)                      \
  XX(205, RESET_CONTENT,                   Reset Content)                   \
  XX(206, PARTIAL_CONTENT,                 Partial Content)                 \
  XX(207, MULTI_STATUS,                    Multi-Status)                    \
  XX(208, ALREADY_REPORTED,                Already Reported)                \
  XX(226, IM_USED,                         IM Used)                         \
  XX(300, MULTIPLE_CHOICES,                Multiple Choices)                \
  XX(301, MOVED_PERMANENTLY,               Moved Permanently)               \
  XX(302, FOUND,                           Found)                           \
  XX(303, SEE_OTHER,                       See Other)                       \
  XX(304, NOT_MODIFIED,                    Not Modified)                    \
  XX(305, USE_PROXY,                       Use Proxy)                       \
  XX(307, TEMPORARY_REDIRECT,              Temporary Redirect)              \
  XX(308, PERMANENT_REDIRECT,              Permanent Redirect)              \
  XX(400, BAD_REQUEST,                     Bad Request)                     \
  XX(401, UNAUTHORIZED,                    Unauthorized)                    \
  XX(402, PAYMENT_REQUIRED,                Payment Required)                \
  XX(403, FORBIDDEN,                       Forbidden)                       \
  XX(404, NOT_FOUND,                       Not Found)                       \
  XX(405, METHOD_NOT_ALLOWED,              Method Not Allowed)              \
  XX(406, NOT_ACCEPTABLE,                  Not Acceptable)                  \
  XX(407, PROXY_AUTHENTICATION_REQUIRED,   Proxy Authentication Required)   \
  XX(408, REQUEST_TIMEOUT,                 Request Timeout)                 \
  XX(409, CONFLICT,                        Conflict)                        \
  XX(410, GONE,                            Gone)                            \
  XX(411, LENGTH_REQUIRED,                 Length Required)                 \
  XX(412, PRECONDITION_FAILED,             Precondition Failed)             \
  XX(413, PAYLOAD_TOO_LARGE,               Payload Too Large)               \
  XX(414, URI_TOO_LONG,                    URI Too Long)                    \
  XX(415, UNSUPPORTED_MEDIA_TYPE,          Unsupported Media Type)          \
  XX(416, RANGE_NOT_SATISFIABLE,           Range Not Satisfiable)           \
  XX(417, EXPECTATION_FAILED,              Expectation Failed)              \
  XX(421, MISDIRECTED_REQUEST,             Misdirected Request)             \
  XX(422, UNPROCESSABLE_ENTITY,            Unprocessable Entity)            \
  XX(423, LOCKED,                          Locked)                          \
  XX(424, FAILED_DEPENDENCY,               Failed Dependency)               \
  XX(426, UPGRADE_REQUIRED,                Upgrade Required)                \
  XX(428, PRECONDITION_REQUIRED,           Precondition Required)           \
  XX(429, TOO_MANY_REQUESTS,               Too Many Requests)               \
  XX(431, REQUEST_HEADER_FIELDS_TOO_LARGE, Request Header Fields Too Large) \
  XX(451, UNAVAILABLE_FOR_LEGAL_REASONS,   Unavailable For Legal Reasons)   \
  XX(500, INTERNAL_SERVER_ERROR,           Internal Server Error)           \
  XX(501, NOT_IMPLEMENTED,                 Not Implemented)                 \
  XX(502, BAD_GATEWAY,                     Bad Gateway)                     \
  XX(503, SERVICE_UNAVAILABLE,             Service Unavailable)             \
  XX(504, GATEWAY_TIMEOUT,                 Gateway Timeout)                 \
  XX(505, HTTP_VERSION_NOT_SUPPORTED,      HTTP Version Not Supported)      \
  XX(506, VARIANT_ALSO_NEGOTIATES,         Variant Also Negotiates)         \
  XX(507, INSUFFICIENT_STORAGE,            Insufficient Storage)            \
  XX(508, LOOP_DETECTED,                   Loop Detected)                   \
  XX(510, NOT_EXTENDED,                    Not Extended)                    \
  XX(511, NETWORK_AUTHENTICATION_REQUIRED, Network Authentication Required) \


#define HTTP_CONTENT_TYPE_MAP(XX)                                           \
    XX(1,   HTML,                     text/html)                            \
    XX(2,   TXT,                      text/plain)                           \
    XX(3,   GIF,                      image/gif)                            \
    XX(4,   JPG,                      image/jpeg)                           \
    XX(5,   PNG,                      image/png)                            \
    XX(6,   XHTML,                    application/xhtml+xml)                \
    XX(7,   XML,                      application/xml)                      \
    XX(8,   JSON,                     application/json)                     \
    XX(9,   PDF,                      application/pdf)                      \
    XX(10,  BIN,                      application/octet-stream)             \


const char* http_status_code_msg(int code)
{
    if (__msg == NULL) {
        __msg = new http_status_msg();
        memset(__msg, 0, sizeof(http_status_msg));
#define XX(num, name, string) __msg->msg[num]=#string; __msg->fname[num]=#name;
        HTTP_STATUS_MAP(XX)
#undef XX
    }

    M_ASSERT(code  >= 0 && code <= MAX_STATUS_NUM, "code error");
    return __msg->msg[code];
}

const char* http_content_type(const char* ext)
{
    if (__type == NULL) {
        __type = new http_content_type_msg();
        memset(__type, 0, sizeof(http_content_type_msg));
#define XX(num, name, string) __type->ext[num]=#name; __type->type[num]=#string;
        HTTP_CONTENT_TYPE_MAP(XX)
#undef XX
    }

    std::string ext_str = ext;
    utils::string_upper(ext_str);

    for (int i = 0; i < ARRAY_SIZE(__type->ext); i++) {
        if (__type->ext[i] && ext_str.compare(__type->ext[i]) == 0) {
            return __type->type[i];
        }
    }
    return "";
}


NS_CC_END


