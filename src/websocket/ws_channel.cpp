//
// Created by zhifan zhang on 2022/2/7.
//

#include "ws_channel.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <stdarg.h>
#include "base64.h"
#include "sha1.h"


extern "C"
{
#include "websocket_parser.h"
#include "http_parser.h"
};

#define ARRAY_SIZE(x)      (sizeof(x) / sizeof(x[0]))

namespace ws {
    static char *str_client_req_tpl = "\
GET %s HTTP/1.1\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: %s\r\n\
Host: %s\r\n\
Sec-WebSocket-Protocol: janus-protocol\r\n\
\r\n\
";


    ws_channel::ws_channel() {
        memset(&_io_context, 0, sizeof(io_context));
        memset(&_cur_msg, 0, sizeof(_cur_msg));
        _io_context.ws_parser = new websocket_parser();
        _io_context.ws_settings = new websocket_parser_settings();
        memset(_io_context.ws_parser, 0, sizeof(websocket_parser));

        _io_context.ws_settings->on_frame_body = &_on_frame_body_cb_static;
        _io_context.ws_settings->on_frame_end = &_on_frame_end_cb_static;
        _io_context.ws_settings->on_frame_header = &_on_frame_header_cb_static;

        websocket_parser_init(_io_context.ws_parser);
        _io_context.ws_parser->data = this;

        _io_context.hp_parser = new http_parser();
        http_parser_init(_io_context.hp_parser, HTTP_RESPONSE);
        _io_context.hp_parser->data = this;

        _io_context.hp_settings = new http_parser_settings();
        _io_context.hp_settings->on_status = &_http_parser_set_status_code_static;
        _io_context.hp_settings->on_header_field = &_http_parser_header_data_static;
        _io_context.hp_settings->on_header_value = &_http_parser_header_data_static;
        _io_context.hp_settings->on_body = &_http_parser_set_resp_body_static;

        _io_context.headers = (header_data_t **) malloc(sizeof(header_data_t *) * kMaxHeaders);
        for (int i = 0; i < kMaxHeaders; ++i) {
            _io_context.headers[i] = NULL;
        }
        _io_context.header_index = kIndexName;

        if (pipe(_io_context.pipe_fd) == 0) {
            log_d("create pipe succ, read_fd:%d, write_fd:%d", _io_context.pipe_fd[0], _io_context.pipe_fd[1]);
        }
#ifdef WITH_SSL
        _io_context.trans = new ssl_trans();
        init_ssl();
#endif
    }

    ws_channel::~ws_channel() {
        if (_cur_msg.data && _cur_msg.len > 0) {
            free(_cur_msg.data);
            _cur_msg.data = NULL;
            _cur_msg.len = 0;
        }
#define CLOSE_FD(fd)    if (fd != -1) { ::close(fd); fd = -1; }

        CLOSE_FD(_io_context.pipe_fd[0]);
        CLOSE_FD(_io_context.pipe_fd[1]);
        CLOSE_FD(_io_context.fd);

#undef CLOSE_FD

        delete _io_context.ws_parser;
        delete _io_context.ws_settings;
        delete _io_context.hp_parser;
#ifdef WITH_SSL
        delete _io_context.trans;
        deinit_ssl();
#endif
    }


    int ws_channel::open(const char *url) {
        int ns = snprintf(_io_context.full_url, ARRAY_SIZE(_io_context.full_url), "%s", url);
        if (ns < ARRAY_SIZE(_io_context.full_url)) {
            _io_context.full_url[ns] = '\0';
        }
        int ret = prepare_ws_request();
        if (ret < 0) {
            log_d("prepare_ws_request fail");
            return -1;
        }
        ret = send_ws_request();
        if (ret < 0) {
            log_d("send_ws_request fail");
            return -1;
        }
        log_d("host:%s, port:%d open succ ", _io_context.server_ip, _io_context.port);
        return 0;
    }

    int ws_channel::send_txt(const char *msg, int len) {
        websocket_flags flag = (websocket_flags) (WS_OP_TEXT | WS_FINAL_FRAME | WS_HAS_MASK);
        return write_msg(msg, len, flag);
    }

    int ws_channel::recv_msg(std::string &msg) {
        msg.clear();

        int ret = read_msg();
        if (ret > 0 && _cur_msg.data && _cur_msg.len > 0) {
            msg.append(_cur_msg.data, _cur_msg.len);
            log_d("recv_msg, len:%d, cap:%d, op_code:%d, is_final:%d",
                  _cur_msg.len, _cur_msg.cap, _cur_msg.opcode, _cur_msg.is_final);
        }
        return ret;
    }

    int ws_channel::close() {
        websocket_flags flag = (websocket_flags) (WS_OP_CLOSE | WS_FINAL_FRAME | WS_HAS_MASK);
        return write_msg("bye", 3, flag);
    }

// direct use SSL_read, app will Hang
// use select with timeout to response Quit Signal
    int ws_channel::cycle(std::function<void(std::string &, uint16_t)> callback) {
        struct timeval timeout = {1, 0};

        int r_fd = _io_context.pipe_fd[0];
        int w_fd = _io_context.pipe_fd[1];


        int count = 0;
        while (true) {
            int max_fd = MAX(_io_context.fd, r_fd);
            fd_set read_set;
            memset(&read_set, 0, sizeof(read_set));
            FD_SET(_io_context.fd, &read_set);
            FD_SET(r_fd, &read_set);

            //wait for a reply with a timeout
            int rc = select(max_fd + 1, &read_set, NULL, NULL, &timeout);
            if (rc == 0) {
                count++;
                log_d("cycle select timeout, count:%d ", count);
#if 0
                // FIXME: Test Pipe write msg, notify select break out;
                ssize_t nr = write(w_fd, "s", 1);
                log_d("cycle select, write pipe socket, nr:%zd", nr);
                if (count > 10) {
                    break;
                }
#endif
                continue;
            }
            if (rc < 0) {
                log_d("cycle select error");
                break;
            }

            // socket come data!
            if (FD_ISSET(_io_context.fd, &read_set) && rc > 0) {
                std::string msg;
                recv_msg(msg);
                if (callback) {
                    callback(msg, _cur_msg.opcode);
                }
                log_d("cycle select come data:%s", msg.c_str());
            }

            // pipe socket come data!
            if (FD_ISSET(r_fd, &read_set) && rc > 0) {
                char buf[64] = {0};
                ssize_t nr = read(r_fd, buf, 64);

                log_d("cycle select pipe come data, nr:%zd, data:%s", nr, buf);
            }
        }

        return 0;
    }


    int ws_channel::write_msg(const char *data, int len, int flag) {
        size_t frame_len = websocket_calc_frame_size((websocket_flags) flag, (size_t) len);
        char *frame = (char *) malloc(sizeof(char) * frame_len);
        websocket_build_frame(frame, (websocket_flags) flag, "mask", data, len);
        int ret = -1;

        int pos = 0;
        while (frame_len > pos) {
            ret = SSL_write(_io_context.trans->ssl, frame + pos, frame_len - pos);
            log_d("write req, len:%d, pos:%d, ret:%d, buf:%s", len, pos, ret, data);
            if (ret <= 0) {
                log_d("write msg fail, ret:%d, len:%d", ret, len);
                break;
            } else if (ret > 0) {
                pos += ret;
            }
        }

        free(frame);
        return ret;
    }

    int ws_channel::read_msg() {
        int ret = -1;
        std::string cache;
        while (true) {
            char buf[1024] = {0};
            ssize_t nr = 0;
            nr = SSL_read(_io_context.trans->ssl, buf, 1024);
            if (nr <= 0) {
                log_d("SSL_read fail, ");
                ret = -2;
                break;
            } else if (nr > 0) {
                cache.append(buf, nr);
            }

            // read finish
            if (0 < nr && nr < 1024) {
                ret = nr;
                break;
            }
        }

        // socket error
        if (ret < 0) {
            return ret;
        }

        size_t nb_parsed = websocket_parser_execute(_io_context.ws_parser, _io_context.ws_settings, cache.data(),
                                                    cache.size());
        log_d("read res, nr:%zd, nb_parsed:%zu", cache.size(), nb_parsed);

        if (nb_parsed == cache.size()) {
            log_d("read res, len:%d, body:%s, offset:%zu ", _cur_msg.len, _cur_msg.data, _io_context.ws_parser->offset);
            ret = 1;
        }
        return ret;
    }


    int ws_channel::prepare_ws_request() {
        data_url durl;
        parse_url(_io_context.full_url, durl);

        log_d("url:%s, proto:%s, host:%s, port:%s, path:%s, query:%s",
              durl.full_url_.c_str(),
              durl.protocol_.c_str(),
              durl.host_.c_str(),
              durl.port_.c_str(),
              durl.path_.c_str(),
              durl.query_.c_str());

        int port = 443;
        if (durl.port_.size() == 0 && durl.protocol_.size() > 0) {
            if (durl.protocol_.compare("wss") == 0 || durl.protocol_.compare("https") == 0) {
                port = 443;
            } else if (durl.protocol_.compare("ws") == 0 || durl.protocol_.compare("http") == 0) {
                port = 80;
            }
        }
        struct addrinfo *result, *rp;
        int ret = getaddrinfo(durl.host_.c_str(), NULL, NULL, &result);
        if (ret < 0) {
            log_d("getaddrinfo: url [%s], err [%s]", durl.host_.c_str(), gai_strerror(ret));
            return -1;
        }

        const int LEN = 256;
        char buf[LEN] = {0};
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            memset(buf, 0, sizeof(LEN));
            if (rp->ai_family == AF_INET) {
                if (inet_ntop(rp->ai_family, &(((struct sockaddr_in *) (rp->ai_addr))->sin_addr), buf, sizeof(buf))) {
                    log_d("getaddrinfo: url [%s], ip [%s]", durl.host_.c_str(), buf);
                    break;
                }
            }
        }
        if (strlen(buf) == 0) {
            log_d("getaddrinfo: url [%s], fail", durl.host_.c_str());
            return -1;
        }

        snprintf(_io_context.server_ip, HOST_MAX_LEN, "%s", buf);
        _io_context.port = port;

        std::string new_query = durl.path_ + durl.query_;
        std::string ws_key = init_sec_websocket_key();
        snprintf(_io_context.sec_ws_key, ARRAY_SIZE(_io_context.sec_ws_key), "%s", ws_key.c_str());

        _ws_req = string_format(str_client_req_tpl, new_query.c_str(), ws_key.c_str(), durl.host_.c_str());
        log_d("ws_req:%s ", _ws_req.c_str());

        return 0;
    }

    int ws_channel::send_ws_request() {

        struct sockaddr *saddr = NULL;
        socklen_t saddr_len = 0;

        struct sockaddr_in sock_addr;
        memset(&sock_addr, 0, sizeof(sock_addr));
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(_io_context.port);

        if (inet_pton(AF_INET, _io_context.server_ip, &(sock_addr.sin_addr)) != 0) {
            saddr = (struct sockaddr *) &sock_addr;
            saddr_len = sizeof(struct sockaddr_in);
        }

        if (saddr == NULL) {
            log_d("saddr == null, fail");
            return -1;
        }

        _io_context.fd = socket(AF_INET, SOCK_STREAM, 0);
        if (_io_context.fd < 0) {
            log_d("create fd fail, fd < 0 , fail");
            return -1;
        }

        int ret = connect(_io_context.fd, saddr, saddr_len);
        if (ret < 0) {
            log_d("socket connect fail");
            return -1;
        }
        log_d("connect succ, fd:%d, host:%s, port:%d, ", _io_context.fd, _io_context.server_ip, _io_context.port);

        SSL_set_fd(_io_context.trans->ssl, _io_context.fd);
        ret = SSL_connect(_io_context.trans->ssl);
        log_d("init_ssl, SSL_connect, ret:%d", ret);
        if (ret < 0) {
            log_d("SSL_connect fail, ret:%d", ret);
            switch (SSL_get_error(_io_context.trans->ssl, ret)) //这里出错
            {
                case SSL_ERROR_NONE: log_d("Fun:%s\tSSL_ERROR_NONE,ssl_ret = %d\n", __FUNCTION__, ret);
                    break;
                case SSL_ERROR_WANT_WRITE: log_d("Fun:%s\tSSL_ERROR_WANT_WRITE,ssl_ret = %d\n", __FUNCTION__, ret);
                    break;
                case SSL_ERROR_WANT_READ: log_d("Fun:%s\tSSL_ERROR_WANT_READ,ssl_ret = %d\n", __FUNCTION__, ret);
                    break;
                default:
                    printf("SSL_connect:%s\n", __FUNCTION__);
                    return -1;
            }
            return -1;
        }

        SSL_write(_io_context.trans->ssl, _ws_req.c_str(), _ws_req.size());
        log_d("write req, nr:%zd, buf:%s", _ws_req.size(), _ws_req.c_str());

        ret = -1;
        {
            char buf[1024] = {0};
            ssize_t nr = 0;
            nr = SSL_read(_io_context.trans->ssl, buf, 1024);

            size_t np = http_parser_execute(_io_context.hp_parser, _io_context.hp_settings, buf, nr);
            log_d("read res, nr:%zd, np:%zu, status:%d, buf:%s", nr, np, _io_context.status_code, buf);
            if (np == nr && HTTP_STATUS_SWITCHING_PROTOCOLS == _io_context.status_code) {
                std::string accept_key = find_http_header_map("Sec-WebSocket-Accept");
                std::string securityKey = _io_context.sec_ws_key;
                securityKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                unsigned char hash[20] = {0};
                SHA1_update(securityKey.c_str(), (char *) hash);
                auto solvedHash = base64_encode(hash, sizeof(hash));
                log_d("accept_key:%s, securityKey:%s, solveHash:%s", accept_key.c_str(), securityKey.c_str(),
                      solvedHash.c_str());

                if (solvedHash.compare(accept_key) == 0) {
                    log_d("Sec-WebSocket-Accept valid");
                    ret = 0;
                }
            }

            return ret;

        }
    }


    int ws_channel::init_ssl() {
        log_d("init_ssl");
        SSL_library_init();
        SSL_load_error_strings();
//    OpenSSL_add_all_algorithms();
        _io_context.trans->ctx = SSL_CTX_new(SSLv23_client_method());
//    SSL_CTX_set_options(_io_context.trans->ctx, WOLFSSL_OP_NO_SSLv2);
        SSL_CTX_set_verify(_io_context.trans->ctx, SSL_VERIFY_NONE, 0);
        _io_context.trans->ssl = SSL_new(_io_context.trans->ctx);
        return 0;
    }

    int ws_channel::deinit_ssl() {
        log_d("deinit_ssl");
        SSL_CTX_free(_io_context.trans->ctx);
        SSL_free(_io_context.trans->ssl);
        return 0;
    }

    std::string ws_channel::find_http_header_map(const char *key) {
        std::string ret;
        if (_io_context.headers == NULL) {
            return ret;
        }
        for (int i = 0; i < kMaxHeaders; i++) {
            if (_io_context.headers[i] && strcmp(_io_context.headers[i]->name, key) == 0) {
                ret = _io_context.headers[i]->value;
                break;
            }
        }
        return ret;
    }


    int ws_channel::parse_url(const std::string url_s, data_url &data) {
        if (url_s.length() == 0)
            return -1;

        if (data.full_url_.compare(url_s) != 0) {
            data.full_url_ = url_s;
        }
        std::string::const_iterator uriEnd = url_s.end();

        // get query start
        std::string::const_iterator queryStart = std::find(url_s.begin(), uriEnd, '?');

        // protocol
        std::string::const_iterator protocolStart = url_s.begin();
        std::string::const_iterator protocolEnd = std::find(protocolStart, uriEnd, ':');            //"://");

        if (protocolEnd != uriEnd) {
            std::string prot = &*(protocolEnd);
            if ((prot.length() > 3) && (prot.substr(0, 3) == "://")) {
                data.protocol_ = std::string(protocolStart, protocolEnd);
                protocolEnd += 3;   //      ://
            } else {
                protocolEnd = url_s.begin();  // no protocol
            }
        } else {
            protocolEnd = url_s.begin();  // no protocol
        }

        // host
        std::string::const_iterator hostStart = protocolEnd;
        std::string::const_iterator pathStart = std::find(hostStart, uriEnd, '/');  // get pathStart

        std::string::const_iterator hostEnd = std::find(protocolEnd,
                                                        (pathStart != uriEnd) ? pathStart : queryStart,
                                                        ':');  // check for port

        data.host_ = std::string(hostStart, hostEnd);

        // port
        if ((hostEnd != uriEnd) && ((&*(hostEnd))[0] == ':'))  // we have a port
        {
            hostEnd++;
            std::string::const_iterator portEnd = (pathStart != uriEnd) ? pathStart : queryStart;
            data.port_ = std::string(hostEnd, portEnd);
        }

        // path
        if (pathStart != uriEnd) {
            data.path_ = std::string(pathStart, queryStart);
        }

        // query
        if (queryStart != uriEnd) {
            data.query_ = std::string(queryStart, url_s.end());
        }
        return 0;
    }


    std::string ws_channel::string_format(const std::string fmt, ...) {
        int size = ((int) fmt.size()) * 2 + 50;   // Use a rubric appropriate for your code
        std::string str;
        va_list ap;
        while (1) {     // Maximum two passes on a POSIX system...
            str.resize(size);
            va_start(ap, fmt);
            int n = vsnprintf((char *) str.data(), size, fmt.c_str(), ap);
            va_end(ap);
            if (n > -1 && n < size) {  // Everything worked
                str.resize(n);
                return str;
            }
            if (n > -1)  // Needed size returned
                size = n + 1;   // For null char
            else
                size *= 2;      // Guess at a larger size (OS specific)
        }
        return str;
    }

    std::string ws_channel::init_sec_websocket_key() {
        uint64_t curr_ts = 0;
        {
            struct timeval val;
            gettimeofday(&val, NULL);
            curr_ts = val.tv_sec * 1000 + val.tv_usec / 1000;
        }

        std::string raw = string_format("ws-client %llu", curr_ts);
        std::string base64_raw = base64_encode((unsigned char const *) raw.c_str(), raw.size());
        log_d("base64_raw: %s ", base64_raw.c_str());
        return base64_raw;
    }


    int ws_channel::_on_frame_header_cb_static(websocket_parser *parser) {
        ws_channel *pthis = (ws_channel *) parser->data;

        int opcode = parser->flags & WS_OP_MASK; // gets opcode
        bool is_final = parser->flags & WS_FIN;   // checks is final frame

        pthis->_cur_msg.opcode = opcode;
        pthis->_cur_msg.is_final = is_final;
        pthis->_cur_msg.len = parser->length;

        if (parser->length && pthis->_cur_msg.data == NULL) {
            pthis->_cur_msg.cap = parser->length + 1024;
            pthis->_cur_msg.data = (char *) malloc(
                    pthis->_cur_msg.cap); // allocate memory for frame body, if body exists
        } else if (pthis->_cur_msg.data && pthis->_cur_msg.cap > 0 && pthis->_cur_msg.cap < parser->length) {
            free(pthis->_cur_msg.data);

            pthis->_cur_msg.cap = parser->length + 1024;
            pthis->_cur_msg.data = (char *) malloc(
                    pthis->_cur_msg.cap); // allocate memory for frame body, if body exists
        }
        log_d("_on_frame_header_cb_static, opcode:%d, is_final:%d, length:%zu, cap:%d",
              opcode, is_final, parser->length, pthis->_cur_msg.cap);

        return 0;
    }

    int ws_channel::_on_frame_end_cb_static(websocket_parser *parser) {
        log_d("_on_frame_end_cb_static");
        return 0;
    }

    int ws_channel::_on_frame_body_cb_static(websocket_parser *parser, const char *at, size_t length) {
        log_d("_on_frame_body_cb_static, length:%zu", length);

        ws_channel *pthis = (ws_channel *) parser->data;

        if (parser->flags & WS_HAS_MASK) {
            // if frame has mask, we have to copy and decode data via websocket_parser_copy_masked function
            websocket_parser_decode(&pthis->_cur_msg.data[parser->offset], at, length, parser);
        } else {
            memcpy(&pthis->_cur_msg.data[parser->offset], at, length);
        }
        return 0;
    }

    int ws_channel::_http_parser_set_status_code_static(http_parser *parser, const char *at, size_t length) {
        ws_channel *pthis = (ws_channel *) parser->data;
        uint16_t status_code = (uint16_t) std::strtol(at - 4, NULL, 10);
        pthis->_io_context.status_code = status_code;
        log_d("_http_parser_set_status_code_static, code:%hu", status_code);
        return 0;
    }

    int ws_channel::_http_parser_header_data_static(http_parser *parser, const char *at, size_t length) {
        ws_channel *pthis = (ws_channel *) parser->data;
        if (pthis->_io_context.header_index == kIndexName) {
            header_data_t *data = (header_data_t *) malloc(sizeof(header_data_t));
            memset(data, 0, sizeof(header_data_t));

            uint8_t bfind = 0;
            for (int i = 0; i < kMaxHeaders; ++i) {
                if (pthis->_io_context.headers[i] == NULL) {
                    pthis->_io_context.headers[i] = data;
                    bfind = 1;
                    break;
                }
            }

            if (bfind == 0) {
                free(data);
                log_d("_static_parser_header_data -- exceed kMaxHeaders");
                return 0;
            }

            if (length > HEADER_MAX_LEN) {
                log_d("_static_parser_header_data length > HEADER_MAX_LEN");
            }

            size_t mcp = length > (HEADER_MAX_LEN - 1) ? (HEADER_MAX_LEN - 1) : (length);
            memcpy(data->name, at, mcp);
            pthis->_io_context.header_index = kIndexValue;
        } else if (pthis->_io_context.header_index == kIndexValue) {
            header_data_t *data = NULL;

//            uint8_t bfind = 0;
            int i = 0;
            for (; i < kMaxHeaders; ++i) {
                if (pthis->_io_context.headers[i] == NULL) {
                    break;
                }
            }

            if (i > 0 && i < kMaxHeaders) {
                log_d("_static_parser_header_data find %d ", i - 1);

                data = pthis->_io_context.headers[i - 1];
                if (data) {
                    size_t mcp = length > (HEADER_MAX_LEN - 1) ? (HEADER_MAX_LEN - 1) : (length);
                    memcpy(data->value, at, mcp);
                }

                pthis->_io_context.header_index = kIndexName;

            }

        }


        return 0;
    }

    int ws_channel::_http_parser_set_resp_body_static(http_parser *parser, const char *at, size_t length) {
        log_d("_http_parser_set_resp_body_static,  length:%zu, at:%s", length, at);
        return 0;
    }


    void ws_channel::SHA1_update(const char *src, char *dest) {
        uint8_t digest[SHA1_DIGEST_SIZE + 1] = {0};
        SHA1_CTX ctx;
        SHA1Init(&ctx);
        SHA1Update(&ctx, (const uint8_t *) src, strlen(src));
        SHA1Final(&ctx, (uint8_t *) dest);
        memcpy(digest, dest, SHA1_DIGEST_SIZE);
        log_d("src:%s, dest:%s", src, digest);
    }

}
