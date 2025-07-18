
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_util.h"
#include "ngx_http_lua_ssl.h"
#include "ngx_http_lua_ctx.h"


/**
 * 请求结束时，用于清理ngx.ctx的结构体
 */
typedef struct {
    int              ref;     //ngx.ctx在ctxs数组中的索引  
    lua_State       *vm;
} ngx_http_lua_ngx_ctx_cleanup_data_t;


static ngx_int_t ngx_http_lua_ngx_ctx_add_cleanup(ngx_http_request_t *r,
    ngx_pool_t *pool, int ref);
static void ngx_http_lua_ngx_ctx_cleanup(void *data);


/**
 * 设置ngx.ctx的一个辅助方法
 * r: 当前请求
 * ctx: 当前请求的ngx_http_lua模块上下文结构体
 */
int
ngx_http_lua_ngx_set_ctx_helper(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, int index)
{
    ngx_pool_t              *pool;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    //如果当前请求的ctx->ctx_ref未设置
    if (ctx->ctx_ref == LUA_NOREF) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua create ngx.ctx table for the current request");

        lua_pushliteral(L, ngx_http_lua_ctx_tables_key);
        lua_rawget(L, LUA_REGISTRYINDEX);
        //将index处的ctx放入ctx_tables中
        lua_pushvalue(L, index);
        ctx->ctx_ref = luaL_ref(L, -2);
        lua_pop(L, 1);

        pool = r->pool;
        //添加ctx_cleanup
        if (ngx_http_lua_ngx_ctx_add_cleanup(r, pool, ctx->ctx_ref) != NGX_OK) {
            return luaL_error(L, "no memory");
        }

        return 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua fetching existing ngx.ctx table for the current "
                   "request");

    lua_pushliteral(L, ngx_http_lua_ctx_tables_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    luaL_unref(L, -1, ctx->ctx_ref);
    lua_pushvalue(L, index);
    ctx->ctx_ref = luaL_ref(L, -2);
    lua_pop(L, 1);

    return 0;
}


/**
 * 获取ngx.ctx 在ctxs数组中的的索引值
 * 
 * 读取的是ngx_http_lua_module上下文结构体ngx_http_lua_ctx_t的ctx_ref字段
 */
int
ngx_http_lua_ffi_get_ctx_ref(ngx_http_request_t *r, int *in_ssl_phase,
    int *ssl_ctx_ref)
{
    ngx_http_lua_ctx_t              *ctx;
#if (NGX_HTTP_SSL)
    ngx_http_lua_ssl_ctx_t          *ssl_ctx;
#endif

    //获取ngx_http_lua_module上下文结构体
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    //返回ctx->ctx_ref
    if (ctx->ctx_ref >= 0 || in_ssl_phase == NULL) {
        return ctx->ctx_ref;
    }

    *in_ssl_phase = ctx->context & (NGX_HTTP_LUA_CONTEXT_SSL_CERT
                                    | NGX_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO
                                    | NGX_HTTP_LUA_CONTEXT_SSL_SESS_FETCH
                                    | NGX_HTTP_LUA_CONTEXT_SSL_SESS_STORE);
    *ssl_ctx_ref = LUA_NOREF;

#if (NGX_HTTP_SSL)
    if (r->connection->ssl != NULL) {
        ssl_ctx = ngx_http_lua_ssl_get_ctx(r->connection->ssl->connection);

        if (ssl_ctx != NULL) {
            *ssl_ctx_ref = ssl_ctx->ctx_ref;
        }
    }
#endif

    //未定义
    return LUA_NOREF;
}


/**
 * 设置ngx.ctx 在ctxs数组中的的索引值
 */
int
ngx_http_lua_ffi_set_ctx_ref(ngx_http_request_t *r, int ref)
{
    ngx_pool_t                      *pool;
    ngx_http_lua_ctx_t              *ctx;
#if (NGX_HTTP_SSL)
    ngx_connection_t                *c;
    ngx_http_lua_ssl_ctx_t          *ssl_ctx;
#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_HTTP_LUA_FFI_NO_REQ_CTX;
    }

#if (NGX_HTTP_SSL)
    if (ctx->context & (NGX_HTTP_LUA_CONTEXT_SSL_CERT
                        | NGX_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO
                        | NGX_HTTP_LUA_CONTEXT_SSL_SESS_FETCH
                        | NGX_HTTP_LUA_CONTEXT_SSL_SESS_STORE))
    {
        ssl_ctx = ngx_http_lua_ssl_get_ctx(r->connection->ssl->connection);
        if (ssl_ctx == NULL) {
            return NGX_ERROR;
        }

        ssl_ctx->ctx_ref = ref;
        c = ngx_ssl_get_connection(r->connection->ssl->connection);
        pool = c->pool;

    } else {
        pool = r->pool;
    }

#else
    pool = r->pool;
#endif

    ctx->ctx_ref = ref;

    //添加一个请求结束时的回调
    if (ngx_http_lua_ngx_ctx_add_cleanup(r, pool, ref) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * 添加一个请求结束时的回调，用于清理ngx.ctx(从ctxs数组中将ngx.ctx移除)
 */
static ngx_int_t
ngx_http_lua_ngx_ctx_add_cleanup(ngx_http_request_t *r, ngx_pool_t *pool,
    int ref)
{
    lua_State                   *L;
    ngx_pool_cleanup_t          *cln;
    ngx_http_lua_ctx_t          *ctx;

    ngx_http_lua_ngx_ctx_cleanup_data_t    *data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    L = ngx_http_lua_get_lua_vm(r, ctx);

    //添加一个ngx_http_lua_ngx_ctx_cleanup_data_t结构体
    cln = ngx_pool_cleanup_add(pool,
                               sizeof(ngx_http_lua_ngx_ctx_cleanup_data_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    //设置回调方法
    cln->handler = ngx_http_lua_ngx_ctx_cleanup;

    data = cln->data;
    data->vm = L;
    data->ref = ref;

    return NGX_OK;
}


/**
 * 请求结束时的回调，用于清理ngx.ctx
 */
static void
ngx_http_lua_ngx_ctx_cleanup(void *data)
{
    lua_State       *L;

    ngx_http_lua_ngx_ctx_cleanup_data_t    *clndata = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua release ngx.ctx at ref %d", clndata->ref);

    L = clndata->vm;

    lua_pushliteral(L, ngx_http_lua_ctx_tables_key);
    //获取ctxs数组
    lua_rawget(L, LUA_REGISTRYINDEX);
    //将其ref位置释放
    luaL_unref(L, -1, clndata->ref);
    lua_pop(L, 1);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
