
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_shdict.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_api.h"


static int ngx_http_lua_shdict_expire(ngx_http_lua_shdict_ctx_t *ctx,
    ngx_uint_t n);
static ngx_int_t ngx_http_lua_shdict_lookup(ngx_shm_zone_t *shm_zone,
    ngx_uint_t hash, u_char *kdata, size_t klen,
    ngx_http_lua_shdict_node_t **sdp);
static int ngx_http_lua_shdict_flush_expired(lua_State *L);
static int ngx_http_lua_shdict_get_keys(lua_State *L);
static int ngx_http_lua_shdict_lpush(lua_State *L);
static int ngx_http_lua_shdict_rpush(lua_State *L);
static int ngx_http_lua_shdict_push_helper(lua_State *L, int flags);
static int ngx_http_lua_shdict_lpop(lua_State *L);
static int ngx_http_lua_shdict_rpop(lua_State *L);
static int ngx_http_lua_shdict_pop_helper(lua_State *L, int flags);
static int ngx_http_lua_shdict_llen(lua_State *L);


static ngx_inline ngx_shm_zone_t *ngx_http_lua_shdict_get_zone(lua_State *L,
    int index);


#define NGX_HTTP_LUA_SHDICT_ADD         0x0001
#define NGX_HTTP_LUA_SHDICT_REPLACE     0x0002
#define NGX_HTTP_LUA_SHDICT_SAFE_STORE  0x0004


#define NGX_HTTP_LUA_SHDICT_LEFT        0x0001
#define NGX_HTTP_LUA_SHDICT_RIGHT       0x0002


enum {
    SHDICT_USERDATA_INDEX = 1,
};


enum {
    SHDICT_TNIL = 0,        /* same as LUA_TNIL */
    SHDICT_TBOOLEAN = 1,    /* same as LUA_TBOOLEAN */
    SHDICT_TNUMBER = 3,     /* same as LUA_TNUMBER */
    SHDICT_TSTRING = 4,     /* same as LUA_TSTRING */
    SHDICT_TLIST = 5,       /* list，这是一个特殊的双端队列类型，用于实现lpush rpush */
};


static ngx_inline ngx_queue_t *
ngx_http_lua_shdict_get_list_head(ngx_http_lua_shdict_node_t *sd, size_t len)
{
    return (ngx_queue_t *) ngx_align_ptr(((u_char *) &sd->data + len),
                                         NGX_ALIGNMENT);
}


/**
 * (ngx_shm_zone_t)zone->init = ngx_http_lua_shdict_init_zone; 见 lua_shared_dict配置指令的解析函数 ngx_http_lua_shared_dict
 * 
 * 这个函数完成了共享内存字典的初始化，主要是红黑树和 LRU 队列的初始化.
 * 
 */
ngx_int_t
ngx_http_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_lua_shdict_ctx_t  *octx = data;

    size_t                      len;
    ngx_http_lua_shdict_ctx_t  *ctx;

    dd("init zone");

    ctx = shm_zone->data;

    /* reload */
    if (octx) {
        // 如果执行 reload 命令，则会继承已经初始化过的数据
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    /* slab 管理器存放在整块共享内存的最前面 */
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        // master 会把初始化搞定，子进程执行到这里就会发现已经初始化完成了。
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

     // 一般只有 master 才会到达这里，先用共享内存创建共享内存字典的内存分配表结构 ngx_http_lua_shdict_shctx_t 
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_lua_shdict_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

     /* 
    * slab 的 data 成员用法通常是由模块自己决定的，
    * 这里用来存放 ngx_http_lua_shm_dict_shctx_t
    */
    ctx->shpool->data = ctx->sh;

    /* 初始化红黑树和 LRU 队列 */
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_lua_shdict_rbtree_insert_value);

    //初始化 lru 队列，同样是用来管理键值对的，空间不足时，就淘汰旧的键值对。
    ngx_queue_init(&ctx->sh->lru_queue);

    len = sizeof(" in lua_shared_dict zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in lua_shared_dict zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


/**
 * 红黑树的节点插入函数
 */
void
ngx_http_lua_shdict_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_lua_shdict_node_t   *sdn, *sdnt;

     // 在 temp 节点上插入 node ， sentinel 是哨兵节点
    for ( ;; ) {

         // 通过对 hash 的比较，决定往左右查找
        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            // 比较 hash 发现 hash 已经存在节点，按 key 比较结果再决定左右节点查找
            sdn = (ngx_http_lua_shdict_node_t *) &node->color;
            sdnt = (ngx_http_lua_shdict_node_t *) &temp->color;

            p = ngx_memn2cmp(sdn->data, sdnt->data, sdn->key_len,
                             sdnt->key_len) < 0 ? &temp->left : &temp->right;
        }

        // 直到找到的节点等于哨兵节点，也就是这个节点不存在退出查找循环。
        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    // 把节点插入到 temp 节点中，并初始化其父节点左右节点
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


/**
 * ngx.shared.DICT.get 根据Key查找
 * **sdp: 出参，为根据key查找到的节点
 * 
 * 返回 NGX_DECLINED：未找到
 *     NGX_DONE: 找到，已过期
 *     NGX_OK: 找到
 */
static ngx_int_t
ngx_http_lua_shdict_lookup(ngx_shm_zone_t *shm_zone, ngx_uint_t hash,
    u_char *kdata, size_t klen, ngx_http_lua_shdict_node_t **sdp)
{
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    uint64_t                     now;
    int64_t                      ms;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    //红黑树查找
    while (node != sentinel) {

        //先使用hash作为红黑树的key进行查找
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (ngx_http_lua_shdict_node_t *) &node->color;

        //再比较真实的key
        rc = ngx_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        //如果key相等，说明找到了
        if (rc == 0) {
            //找到
            *sdp = sd;

            dd("node expires: %lld", (long long) sd->expires);

            if (sd->expires != 0) {
                tp = ngx_timeofday();

                now = (uint64_t) tp->sec * 1000 + tp->msec;
                ms = sd->expires - now;

                dd("time to live: %lld", (long long) ms);

                //已经过期失效
                if (ms <= 0) {
                    dd("node already expired");
                    return NGX_DONE;
                }
            }

            //将当前节点移动到lru_queue队列头部
            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    //未找到
    *sdp = NULL;

    return NGX_DECLINED;
}


/**
 * ngx.shared.DICT 过期节点清理
 * n: n == 1 deletes one or two expired entries
 *    n == 0 deletes oldest entry by force and one or two zero rate entries
 * 返回: 被清理的节点数量
 */
static int
ngx_http_lua_shdict_expire(ngx_http_lua_shdict_ctx_t *ctx, ngx_uint_t n)
{
    ngx_time_t                      *tp;
    uint64_t                         now;
    ngx_queue_t                     *q, *list_queue, *lq;
    int64_t                          ms;
    ngx_rbtree_node_t               *node;
    ngx_http_lua_shdict_node_t      *sd;
    int                              freed = 0;
    ngx_http_lua_shdict_list_node_t *lnode;

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /*
     * n == 1 deletes one or two expired entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

     //最多删除 3 个数据，n 是传进来的
    while (n < 3) {

        //如果是空的
        if (ngx_queue_empty(&ctx->sh->lru_queue)) {
            return freed;
        }

        //最后一个节点
        q = ngx_queue_last(&ctx->sh->lru_queue);

        //节点数据
        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        //如果n为0, 则强制删除最老的节点
        if (n++ != 0) {
            //n不为0

            //此节点无过期时间
            if (sd->expires == 0) {
                return freed;
            }

            //最老的节点未过期
            ms = sd->expires - now;
            if (ms > 0) {
                return freed;
            }
        }

        //如果value类型是list，则遍历list，释放其所有元素
        if (sd->value_type == SHDICT_TLIST) {
            list_queue = ngx_http_lua_shdict_get_list_head(sd, sd->key_len);

            for (lq = ngx_queue_head(list_queue);
                 lq != ngx_queue_sentinel(list_queue);
                 lq = ngx_queue_next(lq))
            {
                lnode = ngx_queue_data(lq, ngx_http_lua_shdict_list_node_t,
                                       queue);

                ngx_slab_free_locked(ctx->shpool, lnode);
            }
        }

        //从lru队列中移除
        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        //从红黑树中移除
        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        //释放node
        ngx_slab_free_locked(ctx->shpool, node);

        //释放节点个数+1
        freed++;
    }

    return freed;
}


/**
 * 注入ngx.shared.*相关api
 */
void
ngx_http_lua_inject_shdict_api(ngx_http_lua_main_conf_t *lmcf, lua_State *L)
{
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_uint_t                   i;
    ngx_shm_zone_t             **zone;
    ngx_shm_zone_t             **zone_udata;

    //如果配置的有shared_dic
    if (lmcf->shdict_zones != NULL) {
        //创建ngx.shared表，表hash元素个数为shared_dic个数
        lua_createtable(L, 0, lmcf->shdict_zones->nelts /* nrec */);
                /* ngx.shared */

        //ngx.shared的元表
        /* 事实上所有的 API 都存放在一个新建的表，这个表将作为所有共享内存字典的元表 */
        lua_createtable(L, 0 /* narr */, 22 /* nrec */); /* shared mt */

        //元表的lpush方法
        lua_pushcfunction(L, ngx_http_lua_shdict_lpush);
        lua_setfield(L, -2, "lpush");

        //元表的rpush方法
        lua_pushcfunction(L, ngx_http_lua_shdict_rpush);
        lua_setfield(L, -2, "rpush");

        //元表的lpop方法
        lua_pushcfunction(L, ngx_http_lua_shdict_lpop);
        lua_setfield(L, -2, "lpop");

        //元表的rpop方法
        lua_pushcfunction(L, ngx_http_lua_shdict_rpop);
        lua_setfield(L, -2, "rpop");

        //元表的llen方法
        lua_pushcfunction(L, ngx_http_lua_shdict_llen);
        lua_setfield(L, -2, "llen");

        //元表的flush_expired方法
        lua_pushcfunction(L, ngx_http_lua_shdict_flush_expired);
        lua_setfield(L, -2, "flush_expired");

        //元表的get_keys方法
        lua_pushcfunction(L, ngx_http_lua_shdict_get_keys);
        lua_setfield(L, -2, "get_keys");

        lua_pushvalue(L, -1); /* shared mt mt */
        //设置元表
        lua_setfield(L, -2, "__index"); /* shared mt */

        zone = lmcf->shdict_zones->elts;

        //遍历shdict_zones动态数组
        for (i = 0; i < lmcf->shdict_zones->nelts; i++) {
            ctx = zone[i]->data;

            //push key shdict名字
            lua_pushlstring(L, (char *) ctx->name.data, ctx->name.len);
                /* shared mt key */

            /* 创建出每个共享内存对应的共享内存字典，也就是一张 Lua table */
            lua_createtable(L, 1 /* narr */, 0 /* nrec */);
                /* table of zone[i] */
            zone_udata = lua_newuserdata(L, sizeof(ngx_shm_zone_t *));
                /* shared mt key ud */
            *zone_udata = zone[i];
            /* 这里将每个共享内存字典对应的 ngx_http_lua_shm_zone_ctx_t 存放在新建的表数组部分，为了后续使用的 API 函数里可以方便拿到这个结构 */
            //ngx.shared.key=zone_udata
            lua_rawseti(L, -2, SHDICT_USERDATA_INDEX); /* {zone[i]} */
            lua_pushvalue(L, -3); /* shared mt key ud mt */
            lua_setmetatable(L, -2); /* shared mt key ud */
            lua_rawset(L, -4); /* shared mt */
        }

        lua_pop(L, 1); /* shared */

    } else {
        lua_newtable(L);    /* ngx.shared */
    }

    lua_setfield(L, -2, "shared");
}


/**
 * 根据index从栈中获取 ngx_shm_zone_t
 */
static ngx_inline ngx_shm_zone_t *
ngx_http_lua_shdict_get_zone(lua_State *L, int index)
{
    ngx_shm_zone_t      *zone;
    ngx_shm_zone_t     **zone_udata;

    lua_rawgeti(L, index, SHDICT_USERDATA_INDEX);
    zone_udata = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (zone_udata == NULL) {
        return NULL;
    }

    zone = *zone_udata;
    return zone;
}


/**
 * syntax: flushed = ngx.shared.DICT:flush_expired(max_count?)
 * 
 * 释放已过期节点，最多释放max_count个。如果max_count为0，则释放所有已过期节点
 */
static int
ngx_http_lua_shdict_flush_expired(lua_State *L)
{
    ngx_queue_t                     *q, *prev, *list_queue, *lq;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_shm_zone_t                  *zone;
    ngx_time_t                      *tp;
    int                              freed = 0;
    int                              attempts = 0;
    ngx_rbtree_node_t               *node;
    uint64_t                         now;
    int                              n;
    ngx_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    if (n == 2) {
        //最多释放的节点个数
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    //如果已经是空的了，直接返回0
    if (ngx_queue_empty(&ctx->sh->lru_queue)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnumber(L, 0);
        return 1;
    }

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    //从最老的节点开始释放
    q = ngx_queue_last(&ctx->sh->lru_queue);

    //遍历lru链表
    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        //如果已过期
        if (sd->expires != 0 && sd->expires <= now) {

            //如果是list,释放list内所有节点
            if (sd->value_type == SHDICT_TLIST) {
                list_queue = ngx_http_lua_shdict_get_list_head(sd, sd->key_len);

                for (lq = ngx_queue_head(list_queue);
                     lq != ngx_queue_sentinel(list_queue);
                     lq = ngx_queue_next(lq))
                {
                    lnode = ngx_queue_data(lq, ngx_http_lua_shdict_list_node_t,
                                           queue);

                    ngx_slab_free_locked(ctx->shpool, lnode);
                }
            }

            ngx_queue_remove(q);

            node = (ngx_rbtree_node_t *)
                ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);
            ngx_slab_free_locked(ctx->shpool, node);
            //释放节点数+1
            freed++;

            //如果达到已释放节点数量
            if (attempts && freed == attempts) {
                break;
            }
        }

        q = prev;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    //返回已释放节点数
    lua_pushnumber(L, freed);
    return 1;
}


/*
 * This trades CPU for memory. This is potentially slow. O(2n)
 */

 /**
  * 这个 api 用时间换空间，有可能比较慢，最坏情况 O(2n)
  * 为了确定输出 table 的元素数量上，多做了一次遍历，输出的 table 因此有了确定的元素数量而不会自动扩展内存
  * 
  * syntax: keys = ngx.shared.DICT:get_keys(max_count?)
  * 
  * Fetch a list of the keys from the dictionary, up to <max_count>.
  */
static int
ngx_http_lua_shdict_get_keys(lua_State *L)
{
    ngx_queue_t                 *q, *prev;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t              *zone;
    ngx_time_t                  *tp;
    int                          total = 0;
    int                          attempts = 1024;
    uint64_t                     now;
    int                          n;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), "
                          "but saw %d", n);
    }

    // this 应该是一个表
    luaL_checktype(L, 1, LUA_TTABLE);

    // 把 zone 从 this 取出
    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    if (n == 2) {
        //最多返回key个数，默认1024
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    //如果lru队列为空，返回一张空表
    if (ngx_queue_empty(&ctx->sh->lru_queue)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_createtable(L, 0, 0);
        return 1;
    }

    // 获取当前时间
    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /* first run through: get total number of elements we need to allocate */

    //从最老的节点开始遍历lru队列， 计算total
    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        //如果节点还没过期
        if (sd->expires == 0 || sd->expires > now) {
            total++;
            //达到最大的返回key个数
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    // 利用 total 事先创建一个大小恰当的输出 table
    lua_createtable(L, total, 0);

    /* second run through: add keys to table */

    total = 0;
    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            //将key加入到结果表中
            lua_pushlstring(L, (char *) sd->data, sd->key_len);
            lua_rawseti(L, -2, ++total);
            //达到最大的返回key个数
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    /* table is at top of stack */
    return 1;
}


/**
 * 暂时没用到
 */
ngx_int_t
ngx_http_lua_shared_dict_get(ngx_shm_zone_t *zone, u_char *key_data,
    size_t key_len, ngx_http_lua_value_t *value)
{
    u_char                      *data;
    size_t                       len;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    if (zone == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key_data, key_len);

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shdict_lookup(zone, hash, key_data, key_len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return rc;
    }

    /* rc == NGX_OK */

    value->type = sd->value_type;

    dd("type: %d", (int) value->type);

    data = sd->data + sd->key_len;
    len = (size_t) sd->value_len;

    switch (value->type) {

    case SHDICT_TSTRING:

        if (value->value.s.data == NULL || value->value.s.len == 0) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no string buffer "
                          "initialized");
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }

        if (len > value->value.s.len) {
            len = value->value.s.len;

        } else {
            value->value.s.len = len;
        }

        ngx_memcpy(value->value.s.data, data, len);
        break;

    case SHDICT_TNUMBER:

        if (len != sizeof(double)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bad lua number "
                          "value size found for key %*s: %lu", key_len,
                          key_data, (unsigned long) len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }

        ngx_memcpy(&value->value.n, data, len);
        break;

    case SHDICT_TBOOLEAN:

        if (len != sizeof(u_char)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bad lua boolean "
                          "value size found for key %*s: %lu", key_len,
                          key_data, (unsigned long) len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }

        value->value.b = *data;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bad lua value type "
                      "found for key %*s: %d", key_len, key_data,
                      (int) value->type);

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_OK;
}


/**
 * ngx.shared.DICT.lpush
 * 
 * syntax: length, err = ngx.shared.DICT:lpush(key, value)
 */
static int
ngx_http_lua_shdict_lpush(lua_State *L)
{
    return ngx_http_lua_shdict_push_helper(L, NGX_HTTP_LUA_SHDICT_LEFT);
}


/**
 * syntax: length, err = ngx.shared.DICT:rpush(key, value)
 */
static int
ngx_http_lua_shdict_rpush(lua_State *L)
{
    return ngx_http_lua_shdict_push_helper(L, NGX_HTTP_LUA_SHDICT_RIGHT);
}


/**
 * lpush/rpush
 */
static int
ngx_http_lua_shdict_push_helper(lua_State *L, int flags)
{
    int                              n;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_str_t                        value;
    int                              value_type;
    double                           num;
    ngx_rbtree_node_t               *node;
    ngx_shm_zone_t                  *zone;
    ngx_queue_t                     *queue, *q;
    ngx_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    //必须3个参数
    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    //获取ngx_shm_zone_t
    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    //key为nil
    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    //从栈中取出key
    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    value_type = lua_type(L, 3);

    switch (value_type) {

    case SHDICT_TSTRING:
        value.data = (u_char *) lua_tolstring(L, 3, &value.len);
        break;

    case SHDICT_TNUMBER:
        value.len = sizeof(double);
        num = lua_tonumber(L, 3);
        value.data = (u_char *) &num;
        break;

    default:
        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    //加进程间锁
    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    /* exists but expired */

    //旧值已过期
    if (rc == NGX_DONE) {

        //如果旧值的类型不是SHDICT_TLIST， 则先释放旧值，然后创建新的
        if (sd->value_type != SHDICT_TLIST) {
            /* TODO: reuse when length matched */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict push: found old entry and value "
                           "type not matched, remove it first");

            //释放掉
            ngx_queue_remove(&sd->queue);

            node = (ngx_rbtree_node_t *)
                        ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);

            ngx_slab_free_locked(ctx->shpool, node);

            dd("go to init_list");
            goto init_list;
        }
        //旧值已经过期，且值的类型为SHDICT_TLIST，则清空SHDICT_TLIST

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict push: found old entry and value "
                       "type matched, reusing it");

        sd->expires = 0;
        sd->value_len = 0;
        /* free list nodes */

        //情况双向链表
        queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

        for (q = ngx_queue_head(queue);
             q != ngx_queue_sentinel(queue);
             q = ngx_queue_next(q))
        {
            /* TODO: reuse matched size list node */
            lnode = ngx_queue_data(q, ngx_http_lua_shdict_list_node_t, queue);
            ngx_slab_free_locked(ctx->shpool, lnode);
        }

        ngx_queue_init(queue);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* exists and not expired */

    //根据key找到了且没有过期
    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TLIST) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a list");
            return 2;
        }

        //将当前节点移动到lru队列的队首
        queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* rc == NGX_DECLINED, not found */

init_list:

    //初始化双向队列
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new entry");

    //申请节点内存
    /* NOTICE: we assume the begin point aligned in slab, be careful */
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key.len
        + sizeof(ngx_queue_t);      //值是一个ngx_queue_t

    dd("length before aligned: %d", n);

    n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

    dd("length after aligned: %d", n);

    //申请节点
    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

    node->key = hash;
    sd->key_len = (u_short) key.len;

    sd->expires = 0;

    sd->value_len = 0;

    dd("setting value type to %d", (int) SHDICT_TLIST);

    sd->value_type = (uint8_t) SHDICT_TLIST;

    //设置Key
    ngx_memcpy(sd->data, key.data, key.len);

    //初始化queue
    ngx_queue_init(queue);

    //加入红黑树
    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    //插入第一个节点
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

push_node:

    //向双向队列queue中插入节点 lpush or rpush 
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new list node");

    //申请一个双向队列节点
    n = offsetof(ngx_http_lua_shdict_list_node_t, data)
        + value.len;

    dd("list node length: %d", n);

    lnode = ngx_slab_alloc_locked(ctx->shpool, n);

    //如果内存申请失败
    if (lnode == NULL) {

        //如果sd的值为空(sd->value_len为list中元素个数)，则将sd整个释放掉
        if (sd->value_len == 0) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict list: no memory for create"
                           " list node and list empty, remove it");

            ngx_queue_remove(&sd->queue);

            node = (ngx_rbtree_node_t *)
                        ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);

            ngx_slab_free_locked(ctx->shpool, node);
        }

        //释放锁
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        //返回 nil, "no memory"
        lua_pushnil(L);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    dd("setting list length to %d", sd->value_len + 1);

    //此时value_len作为queue中的元素个数
    sd->value_len = sd->value_len + 1;

    dd("setting list node value length to %d", (int) value.len);

    //值的长度
    lnode->value_len = (uint32_t) value.len;

    dd("setting list node value type to %d", value_type);

    //值类型
    lnode->value_type = (uint8_t) value_type;

    //拷贝值到lnode->data
    ngx_memcpy(lnode->data, value.data, value.len);

    //lpush or rpush
    if (flags == NGX_HTTP_LUA_SHDICT_LEFT) {
        ngx_queue_insert_head(queue, &lnode->queue);

    } else {
        ngx_queue_insert_tail(queue, &lnode->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    //返回list中元素的个数
    lua_pushnumber(L, sd->value_len);
    return 1;
}


/**
 * syntax: val, err = ngx.shared.DICT:lpop(key)
 */
static int
ngx_http_lua_shdict_lpop(lua_State *L)
{
    return ngx_http_lua_shdict_pop_helper(L, NGX_HTTP_LUA_SHDICT_LEFT);
}


/**
 * syntax: val, err = ngx.shared.DICT:rpop(key)
 */
static int
ngx_http_lua_shdict_rpop(lua_State *L)
{
    return ngx_http_lua_shdict_pop_helper(L, NGX_HTTP_LUA_SHDICT_RIGHT);
}


/**
 * ngx.shared.DICT:lpop/rpop
 */
static int
ngx_http_lua_shdict_pop_helper(lua_State *L, int flags)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_str_t                        value;
    int                              value_type;
    double                           num;
    ngx_rbtree_node_t               *node;
    ngx_shm_zone_t                  *zone;
    ngx_queue_t                     *queue;
    ngx_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    //从栈中获取 ngx_shm_zone_t
    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    //nil key
    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TLIST) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a list");
        return 2;
    }

    //sd->value_len=0是，整个key已经被删除掉了。至少应该>=1
    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua list length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

    if (flags == NGX_HTTP_LUA_SHDICT_LEFT) {
        queue = ngx_queue_head(queue);

    } else {
        queue = ngx_queue_last(queue);
    }

    lnode = ngx_queue_data(queue, ngx_http_lua_shdict_list_node_t, queue);

    value_type = lnode->value_type;

    dd("data: %p", lnode->data);
    dd("value len: %d", (int) sd->value_len);

    value.data = lnode->data;
    value.len = (size_t) lnode->value_len;

    switch (value_type) {

    case SHDICT_TSTRING:

        lua_pushlstring(L, (char *) value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return luaL_error(L, "bad lua list node number value size found "
                              "for key %s in shared_dict %s: %lu", key.data,
                              name.data, (unsigned long) value.len);
        }

        ngx_memcpy(&num, value.data, sizeof(double));

        lua_pushnumber(L, num);
        break;

    default:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad list node value type found for key %s in "
                          "shared_dict %s: %d", key.data, name.data,
                          value_type);
    }

    //从队列中移除
    ngx_queue_remove(queue);

    //释放节点内存
    ngx_slab_free_locked(ctx->shpool, lnode);

    //pop的是最后一个元素
    if (sd->value_len == 1) {

        //释放整个list
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict list: empty node after pop, "
                       "remove it");

        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                    ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

    } else {
        //更新元素个数
        sd->value_len = sd->value_len - 1;

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


/**
 * syntax: len, err = ngx.shared.DICT:llen(key)
 * 如果key不存在，则会返回0；如果值不是list，则返回nil, "value not a list"
 */
static int
ngx_http_lua_shdict_llen(lua_State *L)
{
    int                          n;
    ngx_str_t                    key;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_shm_zone_t              *zone;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    //根据key进行查找
    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TLIST) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a list");
            return 2;
        }

        //将此key移动到队首
        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        //直接返回sd->value_len
        lua_pushnumber(L, (lua_Number) sd->value_len);
        return 1;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    //未找到，返回0
    lua_pushnumber(L, 0);
    return 1;
}


ngx_shm_zone_t *
ngx_http_lua_find_zone(u_char *name_data, size_t name_len)
{
    ngx_str_t                       *name;
    ngx_uint_t                       i;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shm_zone_ctx_t     *ctx;
    volatile ngx_list_part_t        *part;

    part = &ngx_cycle->shared_memory.part;
    zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            zone = part->elts;
            i = 0;
        }

        name = &zone[i].shm.name;

        dd("name: [%.*s] %d", (int) name->len, name->data, (int) name->len);
        dd("name2: [%.*s] %d", (int) name_len, name_data, (int) name_len);

        if (name->len == name_len
            && ngx_strncmp(name->data, name_data, name_len) == 0)
        {
            ctx = (ngx_http_lua_shm_zone_ctx_t *) zone[i].data;
            return &ctx->zone;
        }
    }

    return NULL;
}


ngx_shm_zone_t *
ngx_http_lua_ffi_shdict_udata_to_zone(void *zone_udata)
{
    if (zone_udata == NULL) {
        return NULL;
    }

    return *(ngx_shm_zone_t **) zone_udata;
}


/**
 * syntax: success, err, forcible = ngx.shared.DICT:set(key, value, exptime?, flags?)
 * *key:
 * key_len:
 * value_type:
 * *str_value_buf:
 * str_value_len:
 * num_value: 如果只是number，则此参数不为0
 * forcible:返回参数，标识是否为了本次store，而清理了其他item
 */
int
ngx_http_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op, u_char *key,
    size_t key_len, int value_type, u_char *str_value_buf,
    size_t str_value_len, double num_value, long exptime, int user_flags,
    char **errmsg, int *forcible)
{
    int                          i, n;
    u_char                       c, *p;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    ngx_queue_t                 *queue, *q;
    ngx_rbtree_node_t           *node;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    dd("exptime: %ld", exptime);

    ctx = zone->data;

    *forcible = 0;

    //计算key的hash
    hash = ngx_crc32_short(key, key_len);

    //值的类型
    switch (value_type) {

    case SHDICT_TSTRING:
        /* do nothing */
        break;

    case SHDICT_TNUMBER:
        dd("num value: %lf", num_value);
        str_value_buf = (u_char *) &num_value;
        str_value_len = sizeof(double);
        break;

    case SHDICT_TBOOLEAN:
        c = num_value ? 1 : 0;
        str_value_buf = &c;
        str_value_len = sizeof(u_char);
        break;

    case LUA_TNIL:
        if (op & (NGX_HTTP_LUA_SHDICT_ADD|NGX_HTTP_LUA_SHDICT_REPLACE)) {
            *errmsg = "attempt to add or replace nil values";
            return NGX_ERROR;
        }

        str_value_buf = NULL;
        str_value_len = 0;
        break;

    default:
        *errmsg = "unsupported value type";
        return NGX_ERROR;
    }

    //获取进程间锁
    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    //清理过期节点
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    //根据key进行查找
    rc = ngx_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("lookup returns %d", (int) rc);

    //如果是替换
    if (op & NGX_HTTP_LUA_SHDICT_REPLACE) {

        //未找到
        if (rc == NGX_DECLINED || rc == NGX_DONE) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            *errmsg = "not found";
            return NGX_DECLINED;
        }

        /* rc == NGX_OK */

        goto replace;
    }

    //如果是添加
    if (op & NGX_HTTP_LUA_SHDICT_ADD) {

        //已经存在
        if (rc == NGX_OK) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            *errmsg = "exists";
            return NGX_DECLINED;
        }

        //已经存在，但是已经过期了
        if (rc == NGX_DONE) {
            /* exists but expired */

            dd("go to replace");
            goto replace;
        }

        /* rc == NGX_DECLINED */

        dd("go to insert");
        goto insert;
    }

    if (rc == NGX_OK || rc == NGX_DONE) {

        //表示要删除
        if (value_type == LUA_TNIL) {
            goto remove;
        }

replace:

        if (str_value_buf
            && str_value_len == (size_t) sd->value_len
            && sd->value_type != SHDICT_TLIST)
        {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict set: found old entry and value "
                           "size matched, reusing it");

            //移动到队列头部
            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            //设置过期时间
            if (exptime > 0) {
                tp = ngx_timeofday();
                sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                              + (uint64_t) exptime;

            } else {
                sd->expires = 0;
            }

            //设置flags
            sd->user_flags = user_flags;

            dd("setting value type to %d", value_type);

            sd->value_type = (uint8_t) value_type;

            //替换值，拷贝value
            ngx_memcpy(sd->data + key_len, str_value_buf, str_value_len);

            //解锁
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return NGX_OK;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: found old entry but value size "
                       "NOT matched, removing it first");

remove:

        //删除

        //如果值类型为双向队列
        if (sd->value_type == SHDICT_TLIST) {
            queue = ngx_http_lua_shdict_get_list_head(sd, key_len);

            for (q = ngx_queue_head(queue);
                 q != ngx_queue_sentinel(queue);
                 q = ngx_queue_next(q))
            {
                p = (u_char *) ngx_queue_data(q,
                                              ngx_http_lua_shdict_list_node_t,
                                              queue);

                ngx_slab_free_locked(ctx->shpool, p);
            }
        }

        //从队列中移除
        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        //将node从红黑树中移除
        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        //释放锁
        ngx_slab_free_locked(ctx->shpool, node);

    }

insert:

    /* rc == NGX_DECLINED or value size unmatch */

    //值为NULL
    if (str_value_buf == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict set: creating a new entry");

    //需要的内存
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key_len
        + str_value_len;

    //分配内存
    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {
        //内存分配失败

        //如果不允许剔除其他数据，则直接返回失败
        if (op & NGX_HTTP_LUA_SHDICT_SAFE_STORE) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            *errmsg = "no memory";
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: overriding non-expired items "
                       "due to memory shortage for entry \"%*s\"", key_len,
                       key);

        for (i = 0; i < 30; i++) {
            //尝试清理数据，返回值为清理节点个数
            if (ngx_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            //设置forcible标识用于返回
            *forcible = 1;

            //再尝试分配内存
            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        //内存分配失败，返回错误
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *errmsg = "no memory";
        return NGX_ERROR;
    }

allocated:

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;
    sd->key_len = (u_short) key_len;

    //设置超时时间
    if (exptime > 0) {
        tp = ngx_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        sd->expires = 0;
    }

    sd->user_flags = user_flags;
    sd->value_len = (uint32_t) str_value_len;
    dd("setting value type to %d", value_type);
    sd->value_type = (uint8_t) value_type;

    //复制key
    p = ngx_copy(sd->data, key, key_len);
    //复制value
    ngx_memcpy(p, str_value_buf, str_value_len);

    //插入到红黑树
    ngx_rbtree_insert(&ctx->sh->rbtree, node);
    //插入到lru队列
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


/**
 * syntax: value, flags = ngx.shared.DICT:get(key)
 * *key: key
 * key_len: key长度
 * value_type: 出参, 值的类型,如 LUA_TNIL/SHDICT_TBOOLEAN。参考枚举
 * str_value_buf: 出参, 用于存放value
 * str_value_len: 出参，用于存放value的空间长度
 * get_stale: 是否获取过期值
 * is_stale: 节点是否已经过期
 * 
 */
int
ngx_http_lua_ffi_shdict_get(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, int *value_type, u_char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **err)
{
    ngx_str_t                    name;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_str_t                    value;

    *err = NULL;

    ctx = zone->data;
    name = ctx->name;

    //计算key的hash
    hash = ngx_crc32_short(key, key_len);

#if (NGX_DEBUG)
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%*s\" in shared dict \"%V\"", key_len,
                   key, &name);
#endif /* NGX_DEBUG */

    //获取进程间锁
    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    //如果明确不要返回已过期的值，则先执行过期节点清理逻辑
    if (!get_stale) {
        //传入1， 只尝试删除过期元素
        ngx_http_lua_shdict_expire(ctx, 1);
    }
#endif

    //根据key进行查找
    rc = ngx_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("shdict lookup returns %d", (int) rc);

    //NGX_DECLINED：未找到; NGX_DONE: 找到，但已过期
    if (rc == NGX_DECLINED || (rc == NGX_DONE && !get_stale)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        *value_type = LUA_TNIL;
        return NGX_OK;
    }

    /* rc == NGX_OK || (rc == NGX_DONE && get_stale) */

    *value_type = sd->value_type;

    dd("data: %p", sd->data);
    dd("key len: %d", (int) sd->key_len);

    //获取value
    value.data = sd->data + sd->key_len;
    value.len = (size_t) sd->value_len;

    //如果用于存放value的长度不够
    if (*str_value_len < (size_t) value.len) {
         //如果值类型是bool,直接报错
        if (*value_type == SHDICT_TBOOLEAN) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }

        if (*value_type == SHDICT_TSTRING) {
            //如果值类型是string,则申请新的空间
            *str_value_buf = malloc(value.len);
            if (*str_value_buf == NULL) {
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return NGX_ERROR;
            }
        }
    }

    switch (*value_type) {

    case SHDICT_TSTRING:
        *str_value_len = value.len;
        //复制值
        ngx_memcpy(*str_value_buf, value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "bad lua number value size found for key %*s "
                          "in shared_dict %V: %z", key_len, key,
                          &name, value.len);
            return NGX_ERROR;
        }

        *str_value_len = value.len;
         //复制值
        ngx_memcpy(num_value, value.data, sizeof(double));
        break;

    case SHDICT_TBOOLEAN:

        if (value.len != sizeof(u_char)) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "bad lua boolean value size found for key %*s "
                          "in shared_dict %V: %z", key_len, key, &name,
                          value.len);
            return NGX_ERROR;
        }

         //复制值
        ngx_memcpy(*str_value_buf, value.data, value.len);
        break;

    case SHDICT_TLIST:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *err = "value is a list";
        return NGX_ERROR;

    default:

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "bad value type found for key %*s in "
                      "shared_dict %V: %d", key_len, key, &name,
                      *value_type);
        return NGX_ERROR;
    }

    //返回user_flags
    *user_flags = sd->user_flags;
    dd("user flags: %d", *user_flags);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (get_stale) {

        /* always return value, flags, stale */

        //返回is_stale
        *is_stale = (rc == NGX_DONE);
        return NGX_OK;
    }

    return NGX_OK;
}


/**
 * syntax: newval, err, forcible? = ngx.shared.DICT:incr(key, value, init?, init_ttl?)
 * 
 * 
 */
int
ngx_http_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, double *value, char **err, int has_init, double init,
    long init_ttl, int *forcible)
{
    int                          i, n;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_time_t                  *tp = NULL;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    double                       num;
    ngx_rbtree_node_t           *node;
    u_char                      *p;
    ngx_queue_t                 *queue, *q;

    //初始的ttl
    if (init_ttl > 0) {
        tp = ngx_timeofday();
    }

    ctx = zone->data;

    *forcible = 0;

    //key的hash
    hash = ngx_crc32_short(key, key_len);

    dd("looking up key %.*s in shared dict %.*s", (int) key_len, key,
       (int) ctx->name.len, ctx->name.data);

    //加锁
    ngx_shmtx_lock(&ctx->shpool->mutex);
#if 1
    //尝试清理过期元素
    ngx_http_lua_shdict_expire(ctx, 1);
#endif
    //查找值
    rc = ngx_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    //不存在或已过期
    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        //未设置init，则不进行初始化
        if (!has_init) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            *err = "not found";
            return NGX_ERROR;
        }

        /* add value */
        num = *value + init;

        //已过期
        if (rc == NGX_DONE) {

            /* found an expired item */

            //如果值是number
            if ((size_t) sd->value_len == sizeof(double)
                && sd->value_type != SHDICT_TLIST)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                               "lua shared dict incr: found old entry and "
                               "value size matched, reusing it");

                //将当前节点移动到队列头部
                ngx_queue_remove(&sd->queue);
                ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

                dd("go to setvalue");
                goto setvalue;
            }

            dd("go to remove");
            goto remove;
        }

        dd("go to insert");
        goto insert;
    }

    //这里是正常的找到key，也没有过期的逻辑
    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TNUMBER || sd->value_len != sizeof(double)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        *err = "not a number";
        return NGX_ERROR;
    }

    //将当前节点移动到队列头部
    ngx_queue_remove(&sd->queue);
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    dd("setting value type to %d", (int) sd->value_type);

    p = sd->data + key_len;

    //获取原始值
    ngx_memcpy(&num, p, sizeof(double));
    num += *value;

    //设置新值
    ngx_memcpy(p, (double *) &num, sizeof(double));

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    *value = num;
    return NGX_OK;

remove:

    //已过期，需要先执行remove, 再执行insert
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: found old entry but value size "
                   "NOT matched, removing it first");

    if (sd->value_type == SHDICT_TLIST) {
        queue = ngx_http_lua_shdict_get_list_head(sd, key_len);

        for (q = ngx_queue_head(queue);
             q != ngx_queue_sentinel(queue);
             q = ngx_queue_next(q))
        {
            p = (u_char *) ngx_queue_data(q, ngx_http_lua_shdict_list_node_t,
                                          queue);

            ngx_slab_free_locked(ctx->shpool, p);
        }
    }

    //从lru队列中移除
    ngx_queue_remove(&sd->queue);

    node = (ngx_rbtree_node_t *)
               ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

    //从红黑树中移除
    ngx_rbtree_delete(&ctx->sh->rbtree, node);

    //释放节点
    ngx_slab_free_locked(ctx->shpool, node);

insert:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: creating a new entry");

    //申请新的内存
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key_len
        + sizeof(double);

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    //如果内存申请失败
    if (node == NULL) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict incr: overriding non-expired items "
                       "due to memory shortage for entry \"%*s\"", key_len,
                       key);

        for (i = 0; i < 30; i++) {
            //强制删除最老的节点
            if (ngx_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            *forcible = 1;

            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *err = "no memory";
        return NGX_ERROR;
    }

allocated:

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;

    sd->key_len = (u_short) key_len;

    sd->value_len = (uint32_t) sizeof(double);

    //插入红黑树
    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    //插入头节点
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

setvalue:

    sd->user_flags = 0;

    if (init_ttl > 0) {
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) init_ttl;

    } else {
        sd->expires = 0;
    }

    dd("setting value type to %d", LUA_TNUMBER);

    sd->value_type = (uint8_t) LUA_TNUMBER;

    //拷贝key
    p = ngx_copy(sd->data, key, key_len);
    //拷贝值
    ngx_memcpy(p, (double *) &num, sizeof(double));

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    *value = num;
    return NGX_OK;
}


/**
 * syntax: ngx.shared.DICT:flush_all()
 * 并不会释放内存，只是将所有元素标记为expired
 */
int
ngx_http_lua_ffi_shdict_flush_all(ngx_shm_zone_t *zone)
{
    ngx_queue_t                 *q;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_http_lua_shdict_ctx_t   *ctx;

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    //遍历lru所有节点,将每个阶段的expires设为1
    for (q = ngx_queue_head(&ctx->sh->lru_queue);
         q != ngx_queue_sentinel(&ctx->sh->lru_queue);
         q = ngx_queue_next(q))
    {
        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);
        sd->expires = 1;
    }

    //deletes oldest entry by force and one or two zero rate entries
    ngx_http_lua_shdict_expire(ctx, 0);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


/**
 * 查找节点，返回**sdp
 * 跟ngx_http_lua_shdict_lookup逻辑类似，但不会判断其是否过期，也不会将查找到的节点放到队首
 */
static ngx_int_t
ngx_http_lua_shdict_peek(ngx_shm_zone_t *shm_zone, ngx_uint_t hash,
    u_char *kdata, size_t klen, ngx_http_lua_shdict_node_t **sdp)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (ngx_http_lua_shdict_node_t *) &node->color;

        rc = ngx_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        if (rc == 0) {
            //找到直接返回
            *sdp = sd;

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NGX_DECLINED;
}


/**
 * syntax: ttl, err = ngx.shared.DICT:ttl(key)
 */
long
ngx_http_lua_ffi_shdict_get_ttl(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len)
{
    uint32_t                     hash;
    uint64_t                     now;
    uint64_t                     expires;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    ctx = zone->data;
    hash = ngx_crc32_short(key, key_len);

    //加进程间锁
    ngx_shmtx_lock(&ctx->shpool->mutex);

    //根据key查找，返回sd
    rc = ngx_http_lua_shdict_peek(zone, hash, key, key_len, &sd);

    if (rc == NGX_DECLINED) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_DECLINED;
    }

    /* rc == NGX_OK */

    //返回过期时间
    expires = sd->expires;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (expires == 0) {
        return 0;
    }

    tp = ngx_timeofday();
    now = (uint64_t) tp->sec * 1000 + tp->msec;

    return expires - now;
}


/**
 * syntax: success, err = ngx.shared.DICT:expire(key, exptime)
 * Updates the exptime (in second) of a key-value pair
 */
int
ngx_http_lua_ffi_shdict_set_expire(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, long exptime)
{
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_time_t                  *tp = NULL;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    if (exptime > 0) {
        tp = ngx_timeofday();
    }

    ctx = zone->data;
    hash = ngx_crc32_short(key, key_len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    //根据key查找节点
    rc = ngx_http_lua_shdict_peek(zone, hash, key, key_len, &sd);

    if (rc == NGX_DECLINED) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_DECLINED;
    }

    /* rc == NGX_OK */

    if (exptime > 0) {
        //重设expires
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        //移除过期时间
        sd->expires = 0;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


/**
 * syntax: capacity_bytes = ngx.shared.DICT:capacity()
 */
size_t
ngx_http_lua_ffi_shdict_capacity(ngx_shm_zone_t *zone)
{
    return zone->shm.size;
}


//This feature requires at least Nginx core version 1.11.7.
#if (nginx_version >= 1011007)

/**
 * syntax: free_page_bytes = ngx.shared.DICT:free_space()
 * 
 */
size_t
ngx_http_lua_ffi_shdict_free_space(ngx_shm_zone_t *zone)
{
    size_t                       bytes;
    ngx_http_lua_shdict_ctx_t   *ctx;

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    //返回的是空闲页的大小
    bytes = ctx->shpool->pfree * ngx_pagesize;
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return bytes;
}
#endif


#if (NGX_DARWIN)
int
ngx_http_lua_ffi_shdict_get_macos(ngx_http_lua_shdict_get_params_t *p)
{
    return ngx_http_lua_ffi_shdict_get(p->zone,
                                       (u_char *) p->key, p->key_len,
                                       p->value_type, p->str_value_buf,
                                       p->str_value_len, p->num_value,
                                       p->user_flags, p->get_stale,
                                       p->is_stale, p->errmsg);
}


int
ngx_http_lua_ffi_shdict_store_macos(ngx_http_lua_shdict_store_params_t *p)
{
    return ngx_http_lua_ffi_shdict_store(p->zone, p->op,
                                         (u_char *) p->key, p->key_len,
                                         p->value_type,
                                         (u_char *) p->str_value_buf,
                                         p->str_value_len, p->num_value,
                                         p->exptime, p->user_flags,
                                         p->errmsg, p->forcible);
}


int
ngx_http_lua_ffi_shdict_incr_macos(ngx_http_lua_shdict_incr_params_t *p)
{
    return ngx_http_lua_ffi_shdict_incr(p->zone, (u_char *) p->key, p->key_len,
                                        p->num_value, p->errmsg,
                                        p->has_init, p->init, p->init_ttl,
                                        p->forcible);
}
#endif


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
