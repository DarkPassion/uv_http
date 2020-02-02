# uv_http


## quick start

``` C++

  const char* url = "http://www.zhihu.com/";
  http_request* req = new http_request(url);
  req->set_keep_alive(1);
  req->set_follow_location(1);
  int ret = req->do_work();
  log_d("req->do_work, ret = %d", ret);
  delete req;


```
