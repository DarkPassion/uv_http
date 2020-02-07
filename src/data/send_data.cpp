//
// Created by zhifan zhang on 2020/2/7.
//

#include <string.h>

#include "data/send_data.h"

NS_CC_BEGIN

    void send_data_destory(send_data** s)
    {
        if (s == NULL) {
            return ;
        }

        send_data* sp = *s;

        if (sp->buff_alloc && sp->buf.base) {
            free(sp->buf.base);
            sp->buf.base = NULL;
            sp->buf.len = 0;
        }

        delete sp;
        *s = NULL;
    }


NS_CC_END


