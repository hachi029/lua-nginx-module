
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_uri.h"
#include "ngx_http_lua_util.h"


static int ngx_http_lua_ngx_req_set_uri(lua_State *L);


/**
 * 注入ngx.req.set_uri
 */
void
ngx_http_lua_inject_req_uri_api(ngx_log_t *log, lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_req_set_uri);
    lua_setfield(L, -2, "set_uri");
}


/**
 * https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#ngxreqset_uri
 * 
 * ngx.req.set_uri 
 * 
 * syntax: ngx.req.set_uri(uri, jump?)
 * 
 * jump 默认为false, 指示是否触发重新匹配location， 只能在 rewrite_by_lua*阶段设置
 * 
 * 如果jump为true， ngx.req.set_uri()不会返回
 * 
 */
static int
ngx_http_lua_ngx_req_set_uri(lua_State *L)
{
    ngx_http_request_t          *r;
    size_t                       len;
    u_char                      *p;
    u_char                       byte;
    int                          n;
    int                          jump = 0;
    int                          binary = 0;
    ngx_http_lua_ctx_t          *ctx;
    size_t                       buf_len;
    u_char                      *buf;

    n = lua_gettop(L);

    if (n < 1 || n > 3) {
        return luaL_error(L, "expecting 1, 2 or 3 arguments but seen %d", n);
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ngx_http_lua_check_fake_request(L, r);

    //第1个参数 uri
    p = (u_char *) luaL_checklstring(L, 1, &len);

    if (len == 0) {
        return luaL_error(L, "attempt to use zero-length uri");
    }

    //第三个参数, binary 默认为0
    if (n >= 3) {
        luaL_checktype(L, 3, LUA_TBOOLEAN);
        binary = lua_toboolean(L, 3);
    }

    if (!binary
        && ngx_http_lua_check_unsafe_uri_bytes(r, p, len, &byte) != NGX_OK)
    {
        //计算转义后字符串长度
        buf_len = ngx_http_lua_escape_log(NULL, p, len) + 1;
        //分配空间
        buf = ngx_palloc(r->pool, buf_len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        //进行转义
        ngx_http_lua_escape_log(buf, p, len);
        buf[buf_len - 1] = '\0';

        //抛错返回
        return luaL_error(L, "unsafe byte \"0x%02x\" in uri \"%s\" "
                          "(maybe you want to set the 'binary' argument?)",
                          byte, buf);
    }

    if (n >= 2) {
        //第二个参数
        luaL_checktype(L, 2, LUA_TBOOLEAN);
        jump = lua_toboolean(L, 2);

        if (jump) {

            ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
            if (ctx == NULL) {
                return luaL_error(L, "no ctx found");
            }

            dd("server_rewrite: %d, rewrite: %d, access: %d, content: %d",
               (int) ctx->entered_server_rewrite_phase,
               (int) ctx->entered_rewrite_phase,
               (int) ctx->entered_access_phase,
               (int) ctx->entered_content_phase);

            //jump为true, 只能在rewrite_by_lua*阶段执行
            ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_REWRITE
                                       | NGX_HTTP_LUA_CONTEXT_SERVER_REWRITE);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua set uri jump to \"%*s\"", len, p);

            ngx_http_lua_check_if_abortable(L, ctx);
        }
    }

    //分配空间
    r->uri.data = ngx_palloc(r->pool, len);
    if (r->uri.data == NULL) {
        return luaL_error(L, "no memory");
    }

    //拷贝一份， 重新设置uri
    ngx_memcpy(r->uri.data, p, len);

    r->uri.len = len;

    r->internal = 1;
    r->valid_unparsed_uri = 0;

    //根据新的uri, 重新设置 r->exten
    ngx_http_set_exten(r);

    if (jump) {
        r->uri_changed = 1;

        return lua_yield(L, 0);
    }

    r->valid_location = 0;
    r->uri_changed = 0;

    return 0;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
