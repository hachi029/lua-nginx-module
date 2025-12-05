
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_SOCKET_TCP_H_INCLUDED_
#define _NGX_HTTP_LUA_SOCKET_TCP_H_INCLUDED_


#include "ngx_http_lua_common.h"


#define NGX_HTTP_LUA_SOCKET_FT_ERROR         0x0001
#define NGX_HTTP_LUA_SOCKET_FT_TIMEOUT       0x0002
#define NGX_HTTP_LUA_SOCKET_FT_CLOSED        0x0004
#define NGX_HTTP_LUA_SOCKET_FT_RESOLVER      0x0008
#define NGX_HTTP_LUA_SOCKET_FT_BUFTOOSMALL   0x0010
#define NGX_HTTP_LUA_SOCKET_FT_NOMEM         0x0020
#define NGX_HTTP_LUA_SOCKET_FT_PARTIALWRITE  0x0040
#define NGX_HTTP_LUA_SOCKET_FT_CLIENTABORT   0x0080
#define NGX_HTTP_LUA_SOCKET_FT_SSL           0x0100


typedef struct ngx_http_lua_socket_tcp_upstream_s
        ngx_http_lua_socket_tcp_upstream_t;


typedef struct ngx_http_lua_socket_udata_queue_s
        ngx_http_lua_socket_udata_queue_t;


typedef
    int (*ngx_http_lua_socket_tcp_retval_handler)(ngx_http_request_t *r,
        ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);


typedef void (*ngx_http_lua_socket_tcp_upstream_handler_pt)
    (ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);


/** 
 * ngx.socket.tcp 建立连接时的结构体
 * */ 
typedef struct {
    //关联事件
    ngx_event_t                         event;
    ngx_queue_t                         queue;
    //连接host
    ngx_str_t                           host;
    ngx_http_cleanup_pt                *cleanup;
    ngx_http_lua_socket_tcp_upstream_t *u;
    //连接端口
    in_port_t                           port;
} ngx_http_lua_socket_tcp_conn_op_ctx_t;


#define ngx_http_lua_socket_tcp_free_conn_op_ctx(conn_op_ctx)                \
    ngx_free(conn_op_ctx->host.data);                                        \
    ngx_free(conn_op_ctx)


 /**
  * 表示ngx.socket.tcp场景的一个连接池
  */
typedef struct {
    lua_State                         *lua_vm;

    ngx_int_t                          size;
    //用于复用 ngx_http_lua_socket_tcp_conn_op_ctx_t结构体
    ngx_queue_t                        cache_connect_op;
    //等待从连接池获取连接的队列， 用于限制对某个host:port的连接数量， 元素类型为 ngx_http_lua_socket_tcp_conn_op_ctx_t
    ngx_queue_t                        wait_connect_op;

    /* connections == active connections + pending connect operations,
     * while active connections == out-of-pool reused connections
     *                             + in-pool connections */
    //排队等待获取连接和正在使用的连接数量之和
    //if (spool->connections > spool->size + spool->backlog)
    ngx_int_t                          connections;

    //每个元素是一个可用的已建立的连接
    /* queues of ngx_http_lua_socket_pool_item_t: */
    ngx_queue_t                        cache;
    //未使用的ngx_http_lua_socket_pool_item_t组成的队列
    ngx_queue_t                        free;

    ngx_int_t                          backlog;

    //    size = sizeof(ngx_http_lua_socket_pool_t) - 1 + key_len
    //       + sizeof(ngx_http_lua_socket_pool_item_t) * pool_size;
    //之后是一块连续的内存，先是key，长度为key_len, 之后是pool_size个ngx_http_lua_socket_pool_item_t的数组
    u_char                             key[1];

} ngx_http_lua_socket_pool_t;


/**
 * ngx.socket.tcp()
 * 存储socket信息的上下文结构.这个结构是可重用的，reused保存了重用的次数
 */
struct ngx_http_lua_socket_tcp_upstream_s {
    ngx_http_lua_socket_tcp_retval_handler          read_prepare_retvals;
    ngx_http_lua_socket_tcp_retval_handler          write_prepare_retvals;
    ngx_http_lua_socket_tcp_upstream_handler_pt     read_event_handler;
    ngx_http_lua_socket_tcp_upstream_handler_pt     write_event_handler;

    ngx_http_lua_socket_udata_queue_t              *udata_queue;

    //连接池
    ngx_http_lua_socket_pool_t      *socket_pool;

    ngx_http_lua_loc_conf_t         *conf;
    //注册到r->cleanup的回调函数
    ngx_http_cleanup_pt             *cleanup;
    ngx_http_request_t              *request;
    ngx_peer_connection_t            peer;

    ngx_msec_t                       read_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       connect_timeout;

    //与upstream.resolved类似，表示用于连接的远端的地址
    ngx_http_upstream_resolved_t    *resolved;

    ngx_chain_t                     *bufs_in; /* input data buffers */
    ngx_chain_t                     *buf_in; /* last input data buffer */
    ngx_buf_t                        buffer; /* receive buffer */

    size_t                           length;
    size_t                           rest;

    ngx_err_t                        socket_errno;

    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

    size_t                           request_len;
    ngx_chain_t                     *request_bufs;

    ngx_http_lua_co_ctx_t           *read_co_ctx;
    ngx_http_lua_co_ctx_t           *write_co_ctx;

    //记录连接的复用次数
    ngx_uint_t                       reused;

#if (NGX_HTTP_SSL)
    ngx_str_t                        ssl_name;
    ngx_ssl_session_t               *ssl_session_ret;
    const char                      *error_ret;
    int                              openssl_error_code_ret;
#endif

    ngx_chain_t                     *busy_bufs;

    unsigned                         ft_type:16;
    unsigned                         no_close:1;
    //标识在等待连接建立
    unsigned                         conn_waiting:1;
    //标识正在读取发送数据
    unsigned                         read_waiting:1;
    //标识正在等待发送数据
    unsigned                         write_waiting:1;
    unsigned                         eof:1;
    unsigned                         body_downstream:1;
    unsigned                         raw_downstream:1;
    unsigned                         read_closed:1;
    unsigned                         write_closed:1;
    unsigned                         conn_closed:1;
#if (NGX_HTTP_SSL)
    unsigned                         ssl_verify:1;
    unsigned                         ssl_session_reuse:1;
#endif
};


typedef struct ngx_http_lua_dfa_edge_s  ngx_http_lua_dfa_edge_t;


struct ngx_http_lua_dfa_edge_s {
    u_char                           chr;
    int                              new_state;
    ngx_http_lua_dfa_edge_t         *next;
};


typedef struct {
    ngx_http_lua_socket_tcp_upstream_t  *upstream;

    ngx_str_t                            pattern;
    int                                  state;
    ngx_http_lua_dfa_edge_t            **recovering;

    unsigned                             inclusive:1;
} ngx_http_lua_socket_compiled_pattern_t;


/**
 * ngx.socket.tcp连接池中的一个元素，表示一条缓存的已经打开的连接
 */
typedef struct {
    //指向当前连接所属的连接池
    ngx_http_lua_socket_pool_t      *socket_pool;

    ngx_queue_t                      queue;
    ngx_connection_t                *connection;

    socklen_t                        socklen;
    struct sockaddr_storage          sockaddr;

    //当前连接的复用次数
    ngx_uint_t                       reused;

    ngx_http_lua_socket_udata_queue_t   *udata_queue;
} ngx_http_lua_socket_pool_item_t;


struct ngx_http_lua_socket_udata_queue_s {
    ngx_pool_t                      *pool;
    ngx_queue_t                      queue;
    ngx_queue_t                      free;
    int                              len;
    int                              capacity;
};


typedef struct {
    ngx_queue_t                  queue;
    uint64_t                     key;
    uint64_t                     value;
} ngx_http_lua_socket_node_t;


void ngx_http_lua_inject_socket_tcp_api(ngx_log_t *log, lua_State *L);
void ngx_http_lua_inject_req_socket_api(lua_State *L);
void ngx_http_lua_cleanup_conn_pools(lua_State *L);


#endif /* _NGX_HTTP_LUA_SOCKET_TCP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
