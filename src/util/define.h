//
// Created by zhifan zhang on 2020/1/22.
//

#ifndef UV_HTTP_DEFINE_H
#define UV_HTTP_DEFINE_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>




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


#define ARRAY_SIZE(x)       ((sizeof(x)) / (sizeof(x[0])))

#define SOCKET_TIMEOT_MS        (5000)



#endif //UV_HTTP_DEFINE_H
