
#ifndef _NGX_HTTP_LUA_RINGBUF_H_INCLUDED_
#define _NGX_HTTP_LUA_RINGBUF_H_INCLUDED_


#include "ngx_http_lua_common.h"


/**
 * 用于error_log捕获
 */
typedef struct {
    //捕获的最低级别
    ngx_uint_t   filter_level;
    //tail和head起始都指向buffer的开头
    char        *tail;              /* writed point */
    char        *head;              /* readed point */
    //存放日志的缓冲区，大小由lua_capture_error_log 指令配置
    char        *data;              /* buffer */
    //初始指向*data的结束位置，之后指向tail最右侧的位置。sentinel右侧是无效数据
    char        *sentinel;
    //ua_capture_error_log 指令配置的大小
    size_t       size;              /* buffer total size */
    //日志条数
    size_t       count;             /* count of logs */
} ngx_http_lua_log_ringbuf_t;


void ngx_http_lua_log_ringbuf_init(ngx_http_lua_log_ringbuf_t *rb,
    void *buf, size_t len);
void ngx_http_lua_log_ringbuf_reset(ngx_http_lua_log_ringbuf_t *rb);
ngx_int_t ngx_http_lua_log_ringbuf_read(ngx_http_lua_log_ringbuf_t *rb,
    int *log_level, void **buf, size_t *n, double *log_time);
ngx_int_t ngx_http_lua_log_ringbuf_write(ngx_http_lua_log_ringbuf_t *rb,
    int log_level, void *buf, size_t n);


#endif /* _NGX_HTTP_LUA_RINGBUF_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
