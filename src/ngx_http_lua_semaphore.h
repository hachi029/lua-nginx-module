
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) cuiweixie
 * I hereby assign copyright in this code to the lua-nginx-module project,
 * to be licensed under the same terms as the rest of the code.
 */


#ifndef _NGX_HTTP_LUA_SEMAPHORE_H_INCLUDED_
#define _NGX_HTTP_LUA_SEMAPHORE_H_INCLUDED_


#include "ngx_http_lua_common.h"


/**
 * 代表一个 ngx_http_lua_sema_mm_s 结构体的共享块
 * 
 * 一个共享块内有多个ngx_http_lua_sema_mm_s结构体
 * 
 * 参考 ngx_http_lua_alloc_sema 方法：
 * n = sizeof(ngx_http_lua_sema_mm_block_t)
        + mm->num_per_block * sizeof(ngx_http_lua_sema_t);
 * 
 */
typedef struct ngx_http_lua_sema_mm_block_s {
    //已经使用的 ngx_http_lua_sema_t 个数 (总共有mm->num_per_block 个)
    ngx_uint_t                       used;
    ngx_http_lua_sema_mm_t          *mm;
    //block->epoch = mm->cur_epoch
    ngx_uint_t                       epoch;
} ngx_http_lua_sema_mm_block_t;


/**
 * lmcf->sema_mm
 * 
 * 用于 ngx_http_lua_sema_t 对象缓存
 */
struct ngx_http_lua_sema_mm_s {
    //空闲的 ngx_http_lua_sema_t 队列
    ngx_queue_t                  free_queue;
    //总共分配的 ngx_http_lua_sema_t 结构体数量
    ngx_uint_t                   total;
    //当前正在使用中的 ngx_http_lua_sema_t 的个数
    ngx_uint_t                   used;
    //默认值4095
    ngx_uint_t                   num_per_block;
    //初始化为0，每新创建一个 ngx_http_lua_sema_mm_block_t， epoch+1
    ngx_uint_t                   cur_epoch;
    //所属的配置结构体
    ngx_http_lua_main_conf_t    *lmcf;
};


/**
 * 表示一个semaphore对象
 */
typedef struct ngx_http_lua_sema_s {
    //该semaphore上的等待队列，元素类型为
    ngx_queue_t                          wait_queue;
    ngx_queue_t                          chain;
    //事件，其handler为 ngx_http_lua_sema_handler
    ngx_event_t                          sem_event;
    //所属的 block
    ngx_http_lua_sema_mm_block_t        *block;
    //初始化时传入的n
    int                                  resource_count;
    //在wait_queue上等待的协程数量
    unsigned                             wait_count;
} ngx_http_lua_sema_t;


void ngx_http_lua_sema_mm_cleanup(void *data);
ngx_int_t ngx_http_lua_sema_mm_init(ngx_conf_t *cf,
    ngx_http_lua_main_conf_t *lmcf);


#endif /* _NGX_HTTP_LUA_SEMAPHORE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
