
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_args.h"
#include "ngx_http_lua_util.h"


static int ngx_http_lua_ngx_req_set_uri_args(lua_State *L);
static int ngx_http_lua_ngx_req_get_post_args(lua_State *L);


/**
 * uri 编码，如果dst为NULL，只是计算需要转义的字符个数
 */
uintptr_t
ngx_http_lua_escape_args(u_char *dst, u_char *src, size_t size)
{
    ngx_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

                    /* %00-%20 %7F*/

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000001, /* 0000 0000 0000 0000  0000 0000 0000 0001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };

    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }

            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }

        size--;
    }

    return (uintptr_t) dst;
}


/**
 * https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#ngxreqset_uri_args
 * 
 * ngx.req.set_uri_args(args) args可以是table，也可以是字符串
 * 
 */
static int
ngx_http_lua_ngx_req_set_uri_args(lua_State *L)
{
    ngx_http_request_t          *r;
    ngx_str_t                    args;
    const char                  *msg;
    size_t                       len;
    u_char                      *p;
    uintptr_t                    escape;

    //只接受一个参数
    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting 1 argument but seen %d",
                          lua_gettop(L));
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    //r->connection->fd  == -1 ?
    ngx_http_lua_check_fake_request(L, r);

    switch (lua_type(L, 1)) {
    case LUA_TNUMBER:       //number
        p = (u_char *) lua_tolstring(L, 1, &len);

        args.data = ngx_palloc(r->pool, len);
        if (args.data == NULL) {
            return luaL_error(L, "no memory");
        }

        ngx_memcpy(args.data, p, len);

        args.len = len;
        break;

    case LUA_TSTRING:       //string
        p = (u_char *) lua_tolstring(L, 1, &len);

        //先计算需要转义的字符个数
        escape = ngx_http_lua_escape_args(NULL, p, len);
        if (escape > 0) {
            //有需要转义的字符
            args.len = len + 2 * escape;
            args.data = ngx_palloc(r->pool, args.len);
            if (args.data == NULL) {
                return NGX_ERROR;
            }

            ngx_http_lua_escape_args(args.data, p, len);

        } else {
            //无需要转义的字符
            args.data = ngx_palloc(r->pool, len);
            if (args.data == NULL) {
                return luaL_error(L, "no memory");
            }

            ngx_memcpy(args.data, p, len);

            args.len = len;
        }

        break;

    case LUA_TTABLE:    //table
        ngx_http_lua_process_args_option(r, L, 1, &args);

        dd("args: %.*s", (int) args.len, args.data);

        break;

    default:
        msg = lua_pushfstring(L, "string, number, or table expected, "
                              "but got %s", luaL_typename(L, 1));
        return luaL_argerror(L, 1, msg);
    }

    dd("args: %.*s", (int) args.len, args.data);

    //重置r->args指针
    r->args.data = args.data;
    r->args.len = args.len;

    r->valid_unparsed_uri = 0;

    return 0;
}


/**
 * args, err = ngx.req.get_post_args(max_args?)
 */
static int
ngx_http_lua_ngx_req_get_post_args(lua_State *L)
{
    ngx_http_request_t          *r;
    u_char                      *buf;
    int                          retval;
    size_t                       len;
    ngx_chain_t                 *cl;
    u_char                      *p;
    u_char                      *last;
    int                          n;
    int                          max;

    //参数个数
    n = lua_gettop(L);

    //只能是0或1个参数
    if (n != 0 && n != 1) {
        return luaL_error(L, "expecting 0 or 1 arguments but seen %d", n);
    }

    if (n == 1) {
        max = luaL_checkinteger(L, 1);
        lua_pop(L, 1);

    } else {
        max = NGX_HTTP_LUA_MAX_ARGS;
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ngx_http_lua_check_fake_request(L, r);

    //请求体已经被丢弃
    if (r->discard_body) {
        //创建一个空表
        lua_createtable(L, 0, 0);
        return 1;
    }

    //未读取请求体
    if (r->request_body == NULL) {
        return luaL_error(L, "no request body found; "
                          "maybe you should turn on lua_need_request_body?");
    }

    //请求体太大被读入了临时文件
    if (r->request_body->temp_file) {
        lua_pushnil(L);
        lua_pushliteral(L, "request body in temp file not supported");
        return 2;
    }

    //没有请求体
    if (r->request_body->bufs == NULL) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    /* we copy r->request_body->bufs over to buf to simplify
     * unescaping query arg keys and values */

     //计算请求体长度
    len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        len += cl->buf->last - cl->buf->pos;
    }

    dd("post body length: %d", (int) len);

    if (len == 0) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    //申请内存
    buf = ngx_palloc(r->pool, len);
    if (buf == NULL) {
        return luaL_error(L, "no memory");
    }

    lua_createtable(L, 0, 4);

    //将请求体拷贝到buf
    p = buf;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }

    dd("post body: %.*s", (int) len, buf);

    last = buf + len;

    //解析为table
    retval = ngx_http_lua_parse_args(L, buf, last, max);

    //释放内存
    ngx_pfree(r->pool, buf);

    return retval;
}


/**
 * 解析args字符串 a=b&c=d 为lua table
 * buf: 字符串起始位置
 * last: 字符串结束位置
 * max: 解析的最大数量
 */
int
ngx_http_lua_parse_args(lua_State *L, u_char *buf, u_char *last, int max)
{
    u_char                      *p, *q;
    u_char                      *src, *dst;
    unsigned                     parsing_value;
    size_t                       len;
    int                          count = 0;
    int                          top;

    top = lua_gettop(L);

    p = buf;

    parsing_value = 0;
    q = p;

    while (p != last) {
        if (*p == '=' && ! parsing_value) {
            /* key data is between p and q */

            src = q; dst = q;

            //对key进行uri解码
            ngx_http_lua_unescape_uri(&dst, &src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd("pushing key %.*s", (int) (dst - q), q);

            /* push the key */
            lua_pushlstring(L, (char *) q, dst - q);

            /* skip the current '=' char */
            p++;

            q = p;
            parsing_value = 1;

        } else if (*p == '&') {
            /* reached the end of a key or a value, just save it */
            src = q; dst = q;

            //对key或value进行uri解码
            ngx_http_lua_unescape_uri(&dst, &src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd("pushing key or value %.*s", (int) (dst - q), q);

            /* push the value or key */
            lua_pushlstring(L, (char *) q, dst - q);

            /* skip the current '&' char */
            p++;

            q = p;

            if (parsing_value) {
                /* end of the current pair's value */
                parsing_value = 0;

            } else {
                /* the current parsing pair takes no value,
                 * just push the value "true" */
                dd("pushing boolean true");

                lua_pushboolean(L, 1);
            }

            (void) lua_tolstring(L, -2, &len);

            if (len == 0) {
                /* ignore empty string key pairs */
                dd("popping key and value...");
                lua_pop(L, 2);

            } else {
                dd("setting table...");
                ngx_http_lua_set_multi_value_table(L, top);
            }

            if (max > 0 && ++count == max) {
                lua_pushliteral(L, "truncated");

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                               "lua hit query args limit %d", max);
                return 2;
            }

        } else {
            p++;
        }
    }

    if (p != q || parsing_value) {
        src = q; dst = q;

        ngx_http_lua_unescape_uri(&dst, &src, p - q,
                                  NGX_UNESCAPE_URI_COMPONENT);

        dd("pushing key or value %.*s", (int) (dst - q), q);

        lua_pushlstring(L, (char *) q, dst - q);

        if (!parsing_value) {
            dd("pushing boolean true...");
            lua_pushboolean(L, 1);
        }

        (void) lua_tolstring(L, -2, &len);

        if (len == 0) {
            /* ignore empty string key pairs */
            dd("popping key and value...");
            lua_pop(L, 2);

        } else {
            dd("setting table...");
            ngx_http_lua_set_multi_value_table(L, top);
        }
    }

    dd("gettop: %d", lua_gettop(L));
    dd("type: %s", lua_typename(L, lua_type(L, 1)));

    if (lua_gettop(L) != top) {
        return luaL_error(L, "internal error: stack in bad state");
    }

    return 1;
}


/**
 * 注入api ngx.req.set_uri_args/ngx.req.get_post_args
 */
void
ngx_http_lua_inject_req_args_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_req_set_uri_args);
    lua_setfield(L, -2, "set_uri_args");

    lua_pushcfunction(L, ngx_http_lua_ngx_req_get_post_args);
    lua_setfield(L, -2, "get_post_args");
}


size_t
ngx_http_lua_ffi_req_get_querystring_len(ngx_http_request_t *r)
{
    return r->args.len;
}


/**
 * ngx.req.get_uri_args 会调用此方法， 结果作为ngx_http_lua_ffi_req_get_uri_args方法的传参
 */
int
ngx_http_lua_ffi_req_get_uri_args_count(ngx_http_request_t *r, int max,
    int *truncated)
{
    int                      count;
    u_char                  *p, *last;

    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    *truncated = 0;

    if (max < 0) {
        max = NGX_HTTP_LUA_MAX_ARGS;
    }

    last = r->args.data + r->args.len;
    count = 0;

    //计算&字符的个数
    for (p = r->args.data; p != last; p++) {
        if (*p == '&') {
            if (count == 0) {
                count += 2;

            } else {
                count++;
            }
        }
    }

    //如果count>max, count被置为max， 且truncated被置为1
    if (count) {
        if (max > 0 && count > max) {
            count = max;
            *truncated = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua hit query args limit %d", max);
        }

        return count;
    }

    if (r->args.len) {
        return 1;
    }

    return 0;
}


/**
 * https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#ngxreqget_uri_args
 * 
 * count为args参数个数
 * 返回实际的args参数个数
 */
int
ngx_http_lua_ffi_req_get_uri_args(ngx_http_request_t *r, u_char *buf,
    ngx_http_lua_ffi_table_elt_t *out, int count)
{
    int                          i, parsing_value = 0;
    u_char                      *last, *p, *q;
    u_char                      *src, *dst;

    if (count <= 0) {
        return NGX_OK;
    }

    //先将args参数拷贝到传入的内存。后边解析出来的key和value都指向的是新复制的内存
    ngx_memcpy(buf, r->args.data, r->args.len);

    i = 0;
    last = buf + r->args.len;
    p = buf;
    q = p;

    while (p != last) {
        if (*p == '=' && !parsing_value) {
            /* key data is between p and q */

            src = q; dst = q;

            //对key进行uri解码
            ngx_http_lua_unescape_uri(&dst, &src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd("saving key %.*s", (int) (dst - q), q);

            out[i].key.data = q;
            out[i].key.len = (int) (dst - q);

            /* skip the current '=' char */
            p++;

            q = p;
            parsing_value = 1;

        } else if (*p == '&') {
            /* reached the end of a key or a value, just save it */
            src = q; dst = q;

            //对value进行uri解码
            ngx_http_lua_unescape_uri(&dst, &src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd("pushing key or value %.*s", (int) (dst - q), q);

            if (parsing_value) {
                /* end of the current pair's value */
                parsing_value = 0;

                if (out[i].key.len) {
                    out[i].value.data = q;
                    out[i].value.len = (int) (dst - q);
                    i++;
                }

            } else {
                //没有值的参数
                /* the current parsing pair takes no value,
                 * just push the value "true" */
                dd("pushing boolean true");

                if (dst - q) {
                    out[i].key.data = q;
                    out[i].key.len = (int) (dst - q);
                    out[i].value.len = -1;
                    i++;
                }
            }

            //达到获取的参数个数限制
            if (i == count) {
                return i;
            }

            /* skip the current '&' char */
            p++;

            q = p;

        } else {
            p++;
        }
    }

    if (p != q || parsing_value) {
        src = q; dst = q;

        ngx_http_lua_unescape_uri(&dst, &src, p - q,
                                  NGX_UNESCAPE_URI_COMPONENT);

        dd("pushing key or value %.*s", (int) (dst - q), q);

        if (parsing_value) {
            if (out[i].key.len) {
                out[i].value.data = q;
                out[i].value.len = (int) (dst - q);
                i++;
            }

        } else {
            if (dst - q) {
                out[i].key.data = q;
                out[i].key.len = (int) (dst - q);
                out[i].value.len = (int) -1;
                i++;
            }
        }
    }

    return i;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
