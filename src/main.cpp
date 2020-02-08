//
// Created by zhifan zhang on 2020/1/22.
//

#include <string>
#include "util/logger.h"
#include "test/http_test.h"

USING_NS_CC;


int main(int argc, char** argv)
{

#ifdef TEST_SELF
    http_test ht;
    ht.run_test();
#endif
    return 0;
}





