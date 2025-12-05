
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_SHDICT_H_INCLUDED_
#define _NGX_HTTP_LUA_SHDICT_H_INCLUDED_


#include "ngx_http_lua_common.h"


/**
 * 为ngx_rbtree_node_s.data
 * 
 * ngx.shared.DICT中的一项 kv pair
 * 
 * 共享内存字典就是一张 Lua table，每一对 key-value 在内部都以一个 ngx_http_lua_shdict_node_t 的实例存在
 * 
 * 为了提高检索效率，所有节点被组织成红黑树，同时这些节点又都在一个 LRU 队列上，这是为了快速淘汰节点而设计的
 * 
 */
typedef struct {
    // 事实上这块内存总是连在 ngx_rbtree_node_t 后面
    u_char                       color;
    //值的类型,如LUA_TNIL, 为一个枚举类型。 SHDICT_TLIST = 5, /* list，这是一个特殊的双端队列类型 */
    uint8_t                      value_type;
    //key的长度
    u_short                      key_len;
    //value的长度， 如果值是list，则为list中元素个数
    uint32_t                     value_len;
    //过期时间
    uint64_t                     expires;
    //双向lru队列节点
    ngx_queue_t                  queue;
    //用户set时传入的额外的flags, 在get时可以取出
    uint32_t                     user_flags;
    //存放key+value。前key_len个字节为key，之后value_len个字节为value
    //value.data = sd->data + sd->key_len;
    u_char                       data[1];
} ngx_http_lua_shdict_node_t;


/**
 * ngx.shared.DICT.lpush/rpush 中双向队列的一个节点
 * 如执行lpush就会申请一个此节点的数据结构，将其放入队列。
 * lpop则会释放一个此节点
 */
typedef struct {
    //所在队列
    ngx_queue_t                  queue;
    //值的长度
    uint32_t                     value_len;
    //值的类型
    uint8_t                      value_type;
    u_char                       data[1];
} ngx_http_lua_shdict_list_node_t;


/**
 * ngx.shared.DICT, 红黑树+lru队列
 */
typedef struct {
    //整棵红黑树的根节点
    ngx_rbtree_t                  rbtree;
    //空节点
    ngx_rbtree_node_t             sentinel;
    //lru双向队列
    ngx_queue_t                   lru_queue;
} ngx_http_lua_shdict_shctx_t;


/**
 * 表示一个lua_shared_dict配置指令
 */
typedef struct {
    //用于维护字典实现数据的结构
    ngx_http_lua_shdict_shctx_t  *sh;
    /*是 nginx 提供的 slab 内存分配机制实现的内存池，这里实际操作的是一块共享内存，提供在共享内存中分配内存的功能 */
    ngx_slab_pool_t              *shpool;
    /* 用于保存本共享内存字典的名字，作为唯一识别码存在 */
    ngx_str_t                     name;
    //这里保存了 main 配置的指针，目前只用于判断是否需要延后调用 lmcf->init_handler
    ngx_http_lua_main_conf_t     *main_conf;
    ngx_log_t                    *log;
} ngx_http_lua_shdict_ctx_t;


typedef struct {
    ngx_log_t                   *log;
    ngx_http_lua_main_conf_t    *lmcf;
    ngx_cycle_t                 *cycle;
    /* 指向的共享内存对象 */
    ngx_shm_zone_t               zone;
} ngx_http_lua_shm_zone_ctx_t;


#if (NGX_DARWIN)
typedef struct {
    void                  *zone;
    const unsigned char   *key;
    size_t                 key_len;
    int                   *value_type;
    unsigned char        **str_value_buf;
    size_t                *str_value_len;
    double                *num_value;
    int                   *user_flags;
    int                    get_stale;
    int                   *is_stale;
    char                 **errmsg;
} ngx_http_lua_shdict_get_params_t;


typedef struct {
    void                  *zone;
    int                    op;
    const unsigned char   *key;
    size_t                 key_len;
    int                    value_type;
    const unsigned char   *str_value_buf;
    size_t                 str_value_len;
    double                 num_value;
    long                   exptime;
    int                    user_flags;
    char                 **errmsg;
    int                   *forcible;
} ngx_http_lua_shdict_store_params_t;


typedef struct {
    void                  *zone;
    const unsigned char   *key;
    size_t                 key_len;
    double                *num_value;
    char                 **errmsg;
    int                    has_init;
    double                 init;
    long                   init_ttl;
    int                   *forcible;
} ngx_http_lua_shdict_incr_params_t;
#endif


ngx_int_t ngx_http_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data);
void ngx_http_lua_shdict_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
void ngx_http_lua_inject_shdict_api(ngx_http_lua_main_conf_t *lmcf,
    lua_State *L);


#endif /* _NGX_HTTP_LUA_SHDICT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
