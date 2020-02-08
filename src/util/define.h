//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_DEFINE_H
#define UV_HTTP_DEFINE_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>



// Generic macros
/// @name namespace uv_http
/// @{
#ifdef __cplusplus
#define NS_CC_BEGIN                     namespace uv_http {
#define NS_CC_END                       }
#define USING_NS_CC                     using namespace uv_http
#define NS_CC                           ::uv_http
#else
#define NS_CC_BEGIN
    #define NS_CC_END
    #define USING_NS_CC
    #define NS_CC
#endif





#undef DISALLOW_ASSIGN
#define DISALLOW_ASSIGN(TypeName) \
    void operator=(const TypeName&)

    // A macro to disallow the evil copy constructor and operator= functions
    // This should be used in the private: declarations for a class.

#undef DISALLOW_COPY_AND_ASSIGN
#define DISALLOW_COPY_AND_ASSIGN(TypeName)    \
    private:                                      \
    TypeName(const TypeName&);                    \
    DISALLOW_ASSIGN(TypeName)


#define ARRAY_SIZE(x)           ((sizeof(x)) / (sizeof(x[0])))
#define SOCKET_TIMEOUT_MS        (5000)
#define HTTP_CR                  '\r'
#define HTTP_LF                  '\n'
#define URL_MAX_LEN             (1024)
#define LISTEN_BACKLOG            (128)

#define HTTP_HEADER_TRANSFER_ENCODEING     "Transfer-Encoding"
#define HTTP_HEADER_TRANSFER_CHUNKED       "chunked"
#define HTTP_HEADER_LOCATION                "Location"
#define HTTP_HEADER_CONTENT_LENGTH          "Content-Length"
#define HTTP_HEADER_USER_AGENT              "User-Agent"
#define HTTP_HEADER_CONTENT_TYPE            "Content-Type"
#define HTTP_HEADER_CONNECTION              "Connection"
#define HTTP_HEADER_CONNECTION_CLOSE        "close"
#define HTTP_HEADER_CONNECTION_KEEP_ALIVE   "keep-alive"
#define HTTP_HREADER_CONTENT_ENCODING       "Content-Encoding"
#define HTTP_HREADER_ENCODING_GZIP          "gzip"

#if (defined (_DEBUG) || defined(DEBUG))
#define M_ASSERT(expr, msg)     utils::m_assert(#expr, expr, __FILE__, __LINE__, msg);
#else
#define M_ASSERT(expr, msg)
#endif

#endif //UV_HTTP_DEFINE_H
