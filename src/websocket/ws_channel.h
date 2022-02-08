//
// Created by zhifan zhang on 2022/2/7.
//

#pragma once
#ifndef __WS_CHANNEL_H__
#define __WS_CHANNEL_H__

#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>

#include <wolfssl/openssl/ssl.h>

#define log_d(...)      { printf(__VA_ARGS__); printf("\n"); }

struct websocket_parser;
struct websocket_parser_settings;
struct http_parser;
struct http_parser_settings;

namespace ws {


    class ws_channel {

    public:
        ws_channel();

        ~ws_channel();

    public:
        int open(const char *url);

        int send_txt(const char *msg, int len);

        int recv_msg(std::string &msg);

        int cycle(std::function<void(std::string &msg, uint16_t code)> callback);

        int close();

    private:
        static int _on_frame_body_cb_static(websocket_parser *parser, const char *at, size_t length);

        static int _on_frame_end_cb_static(websocket_parser *parser);

        static int _on_frame_header_cb_static(websocket_parser *parser);

        static int _http_parser_set_status_code_static(http_parser *parser, const char *at, size_t length);

        static int _http_parser_set_resp_body_static(http_parser *parser, const char *at, size_t length);

        static int _http_parser_header_data_static(http_parser *parser, const char *at, size_t length);

    private:
        int init_ssl();

        int deinit_ssl();

        int write_msg(const char *data, int len, int flag);

        int read_msg();

        int prepare_ws_request();

        int send_ws_request();

        std::string find_http_header_map(const char *key);

    private:

        enum {
            kIndexName = 0,
            kIndexValue,
        };

        enum {
            kMaxHeaders = 64,
            HOST_MAX_LEN = 64,
            SEC_WS_KEY_MAX_LEN = 256,
            HEADER_MAX_LEN = 320,
            MAX_URL_LEN = 1024,
        };

        struct ssl_trans {
            SSL_CTX *ctx;
            SSL *ssl;
        };

        struct header_data_t {
            char name[HEADER_MAX_LEN];
            char value[HEADER_MAX_LEN];
        };

        struct io_context {
            char full_url[MAX_URL_LEN];
            char sec_ws_key[SEC_WS_KEY_MAX_LEN];  // Sec-WebSocket-Key

            int pipe_fd[2];
            int fd; // ws socket
            char server_ip[HOST_MAX_LEN];   // ws server ip
            int port;   // ws server port
            struct ssl_trans *trans;
            struct websocket_parser *ws_parser;
            struct websocket_parser_settings *ws_settings;
            struct http_parser *hp_parser;
            struct http_parser_settings *hp_settings;
            struct header_data_t **headers;
            int status_code;
            uint8_t header_index;
        };

        struct wb_msg {
            char *data;
            int len;
            int cap;
            uint16_t opcode;
            uint8_t is_final;
        };

        struct data_url {
            std::string protocol_;
            std::string host_;
            std::string path_;
            std::string query_;
            std::string port_;
            std::string full_url_;
        };

        static int parse_url(const std::string url, data_url &data);

        static std::string string_format(const std::string fmt, ...);

        static std::string init_sec_websocket_key();

        static void SHA1_update(const char *src, char *dest);

    private:
        wb_msg _cur_msg;
        std::string _ws_req;
        io_context _io_context;
    };
}

#endif // __WS_CHANNEL_H__
