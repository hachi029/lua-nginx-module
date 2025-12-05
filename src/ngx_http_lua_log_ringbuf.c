
#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_common.h"
#include "ngx_http_lua_log_ringbuf.h"


/**
 * 日志头
 */
typedef struct {
    //写入日志的时间
    double      time;
    //日志长度
    unsigned    len;
    //写入的日志级别
    unsigned    log_level;
} ngx_http_lua_log_ringbuf_header_t;


enum {
    HEADER_LEN = sizeof(ngx_http_lua_log_ringbuf_header_t),
};


static void *ngx_http_lua_log_ringbuf_next_header(
    ngx_http_lua_log_ringbuf_t *rb);
static void ngx_http_lua_log_ringbuf_append(
    ngx_http_lua_log_ringbuf_t *rb, int log_level, void *buf, int n);
static size_t ngx_http_lua_log_ringbuf_free_spaces(
    ngx_http_lua_log_ringbuf_t *rb);


/**
 * 初始化用于捕获error_log的ngx_http_lua_log_ringbuf_t 结构体
 */
void
ngx_http_lua_log_ringbuf_init(ngx_http_lua_log_ringbuf_t *rb, void *buf,
    size_t len)
{
    rb->data = buf;
    rb->size = len;

    rb->tail = rb->data;
    rb->head = rb->data;
    rb->sentinel = rb->data + rb->size;
    rb->count = 0;
    rb->filter_level = NGX_LOG_DEBUG;

    return;
}


/**
 * 日志条数为1，将ringbuf reset到初始为止
 */
void
ngx_http_lua_log_ringbuf_reset(ngx_http_lua_log_ringbuf_t *rb)
{
    rb->tail = rb->data;
    rb->head = rb->data;
    rb->sentinel = rb->data + rb->size;
    rb->count = 0;

    return;
}


/*
 * get the next data header, it'll skip the useless data space or
 * placehold data
 * 获取下次读的位置
 */
static void *
ngx_http_lua_log_ringbuf_next_header(ngx_http_lua_log_ringbuf_t *rb)
{
    //右侧剩余空间小于HEADER_LEN, 将rb->head重置为rb->data
    /* useless data */
    if (rb->size - (rb->head - rb->data) < HEADER_LEN)
    {
        return rb->data;
    }

    /* placehold data */
    if (rb->head >= rb->sentinel) {
        return rb->data;
    }

    return rb->head;
}


/**
 * 向缓冲区写入日志
 */
/* append data to ring buffer directly */
static void
ngx_http_lua_log_ringbuf_append(ngx_http_lua_log_ringbuf_t *rb,
    int log_level, void *buf, int n)
{
    ngx_http_lua_log_ringbuf_header_t        *head;
    ngx_time_t                               *tp;

    head = (ngx_http_lua_log_ringbuf_header_t *) rb->tail;
    //日志长度
    head->len = n;
    //日志级别
    head->log_level = log_level;

    tp = ngx_timeofday();
    //当前时间
    head->time = tp->sec + tp->msec / 1000.0L;

    rb->tail += HEADER_LEN;
    //拷贝日志内存
    ngx_memcpy(rb->tail, buf, n);
    rb->tail += n;
    //日志条数+1
    rb->count++;

    //重置sentinel
    if (rb->tail > rb->sentinel) {
        rb->sentinel = rb->tail;
    }

    return;
}


/* throw away data at head */
static void
ngx_http_lua_log_ringbuf_throw_away(ngx_http_lua_log_ringbuf_t *rb)
{
    ngx_http_lua_log_ringbuf_header_t       *head;

    if (rb->count == 0) {
        return;
    }

    head = (ngx_http_lua_log_ringbuf_header_t *) rb->head;

    //跳过HEADER_LEN+head->len
    rb->head += HEADER_LEN + head->len;
    //日志条数-1
    rb->count--;

    if (rb->count == 0) {
        //重置ringbuf
        ngx_http_lua_log_ringbuf_reset(rb);
    }

    //获取下次读的位置
    rb->head = ngx_http_lua_log_ringbuf_next_header(rb);

    return;
}


/**
 * 计算ringbuf剩余空间
 */
/* size of free spaces */
static size_t
ngx_http_lua_log_ringbuf_free_spaces(ngx_http_lua_log_ringbuf_t *rb)
{
    if (rb->count == 0) {
        return rb->size;
    }

    //rail指向下一个write的位置; head指向下一个读取的位置
    if (rb->tail > rb->head) {
        return rb->data + rb->size - rb->tail;
    }

    return rb->head - rb->tail;
}


/*
 * 向ringbuf写入日志，如果空间不足，会丢弃最老的日志
 * try to write log data to ring buffer, throw away old data
 * if there was not enough free spaces.
 */
ngx_int_t
ngx_http_lua_log_ringbuf_write(ngx_http_lua_log_ringbuf_t *rb, int log_level,
    void *buf, size_t n)
{
    //HEADER_LEN = sizeof(ngx_http_lua_log_ringbuf_header_t)
    //如果单条日志的长度大于ringbuf的大小
    if (n + HEADER_LEN > rb->size) {
        return NGX_ERROR;
    }

    //计算ringbuf剩余空间
    if (ngx_http_lua_log_ringbuf_free_spaces(rb) < n + HEADER_LEN) {
        //如果右侧的剩余空间不足，只能从左侧起始位置开始写。写之前先要丢弃右侧还没读取的日志
        /* if the right space is not enough, mark it as placehold data */
        if ((size_t)(rb->data + rb->size - rb->tail) < n + HEADER_LEN) {

            //如果读的位置在写的位置右侧，则一直丢弃未读取的日志
            while (rb->head >= rb->tail && rb->count) {
                /* head is after tail, so we will throw away all data between
                 * head and sentinel */
                ngx_http_lua_log_ringbuf_throw_away(rb);
            }

            rb->sentinel = rb->tail;
            rb->tail = rb->data;
        }

        while (ngx_http_lua_log_ringbuf_free_spaces(rb) < n + HEADER_LEN) {
            ngx_http_lua_log_ringbuf_throw_away(rb);
        }
    }

    //写入日志
    ngx_http_lua_log_ringbuf_append(rb, log_level, buf, n);

    return NGX_OK;
}


/**
 * 读取日志
 * *buf:      输出参数，日志内容位置
 * n:         输出参数，日志长度
 * log_level：输出参数，
 * log_time： 输出参数，日志时间
 */
/* read log from ring buffer, do reset if all of the logs were readed. */
ngx_int_t
ngx_http_lua_log_ringbuf_read(ngx_http_lua_log_ringbuf_t *rb, int *log_level,
    void **buf, size_t *n, double *log_time)
{
    ngx_http_lua_log_ringbuf_header_t       *head;

    if (rb->count == 0) {
        return NGX_ERROR;
    }

    head = (ngx_http_lua_log_ringbuf_header_t *) rb->head;

    //rb->sentinel指向的是tail的最右侧位置。sentinel右侧是无效数据
    if (rb->head >= rb->sentinel) {
        return NGX_ERROR;
    }

    //输出日志级别
    *log_level = head->log_level;
    //输出日志长度
    *n = head->len;
    rb->head += HEADER_LEN;
    //
    *buf = rb->head;
    rb->head += head->len;

    //日志时间
    if (log_time) {
        *log_time = head->time;
    }

    //日志条数-1
    rb->count--;

    if (rb->count == 0) {
        ngx_http_lua_log_ringbuf_reset(rb);
    }

    //重置下次读取位置
    rb->head = ngx_http_lua_log_ringbuf_next_header(rb);

    return NGX_OK;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
