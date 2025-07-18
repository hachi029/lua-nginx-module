
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_headers.h"
#include "ngx_http_lua_headers_out.h"
#include "ngx_http_lua_headers_in.h"
#include "ngx_http_lua_util.h"


static int ngx_http_lua_ngx_req_http_version(lua_State *L);
static int ngx_http_lua_ngx_req_raw_header(lua_State *L);
static int ngx_http_lua_ngx_req_header_set_helper(lua_State *L);
static int ngx_http_lua_ngx_resp_get_headers(lua_State *L);
static int ngx_http_lua_ngx_req_header_set(lua_State *L);
#if (nginx_version >= 1011011)
void ngx_http_lua_ngx_raw_header_cleanup(void *data);
#endif


/**
 * 注入api ngx.resp.get_headers
 */
void
ngx_http_lua_inject_resp_header_api(lua_State *L)
{
    lua_createtable(L, 0, 1); /* .resp */

    lua_pushcfunction(L, ngx_http_lua_ngx_resp_get_headers);
    lua_setfield(L, -2, "get_headers");

    lua_setfield(L, -2, "resp");
}


/**
 * api注入
 */
void
ngx_http_lua_inject_req_header_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_req_http_version);
    lua_setfield(L, -2, "http_version");

    lua_pushcfunction(L, ngx_http_lua_ngx_req_raw_header);
    lua_setfield(L, -2, "raw_header");

    lua_pushcfunction(L, ngx_http_lua_ngx_req_header_set);
    lua_setfield(L, -2, "set_header");
}


/**
 * ngx.req.http_version, 读取r->http_version
 */
static int
ngx_http_lua_ngx_req_http_version(lua_State *L)
{
    ngx_http_request_t          *r;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ngx_http_lua_check_fake_request(L, r);

    switch (r->http_version) {
    case NGX_HTTP_VERSION_9:
        lua_pushnumber(L, 0.9);
        break;

    case NGX_HTTP_VERSION_10:
        lua_pushnumber(L, 1.0);
        break;

    case NGX_HTTP_VERSION_11:
        lua_pushnumber(L, 1.1);
        break;

#ifdef NGX_HTTP_VERSION_20
    case NGX_HTTP_VERSION_20:
        lua_pushnumber(L, 2.0);
        break;
#endif

#ifdef NGX_HTTP_VERSION_30
    case NGX_HTTP_VERSION_30:
        lua_pushnumber(L, 3.0);
        break;
#endif

    default:
        lua_pushnil(L);
        break;
    }

    return 1;
}


/**
 * ngx.req.raw_header
 * 
 * https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#ngxreqraw_header
 * 
 *  str = ngx.req.raw_header(no_request_line?)
 * 
 *  获取请求的请求行和所有请求头。no_request_line 参数标识是否返回请求行
 * 
 */
static int
ngx_http_lua_ngx_req_raw_header(lua_State *L)
{
    int                          n, line_break_len;
    u_char                      *data, *p, *last, *pos;
    unsigned                     no_req_line = 0, found;
    size_t                       size;
    ngx_buf_t                   *b, *first = NULL;
    ngx_int_t                    i, j;
#if (nginx_version >= 1011011)
    ngx_buf_t                  **bb;
    ngx_chain_t                 *cl;
    ngx_http_lua_main_conf_t    *lmcf;
#endif
    ngx_connection_t            *c;
    ngx_http_request_t          *r, *mr;
    ngx_http_connection_t       *hc;

    n = lua_gettop(L);
    if (n > 0) {
        no_req_line = lua_toboolean(L, 1);
    }

    //no_req_line 是否返回请求行
    dd("no req line: %d", (int) no_req_line);

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

#if (nginx_version >= 1011011)
    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);
#endif

    ngx_http_lua_check_fake_request(L, r);

    //获取主请求
    mr = r->main;
    hc = mr->http_connection;
    c = mr->connection;

#if (NGX_HTTP_V2)
    if (mr->stream) {
        return luaL_error(L, "http2 requests not supported yet");
    }
#endif

#if 1
    dd("hc->nbusy: %d", (int) hc->nbusy);

    if (hc->nbusy) {
#if (nginx_version >= 1011011)
        dd("hc->busy: %p %p %p %p", hc->busy->buf->start, hc->busy->buf->pos,
           hc->busy->buf->last, hc->busy->buf->end);
#else
        dd("hc->busy: %p %p %p %p", hc->busy[0]->start, hc->busy[0]->pos,
           hc->busy[0]->last, hc->busy[0]->end);
#endif
    }

    dd("request line: %p %p", mr->request_line.data,
       mr->request_line.data + mr->request_line.len);

    dd("header in: %p %p %p %p", mr->header_in->start,
       mr->header_in->pos, mr->header_in->last,
       mr->header_in->end);

    dd("c->buffer: %p %p %p %p", c->buffer->start,
       c->buffer->pos, c->buffer->last,
       c->buffer->end);
#endif

    //记录后续需要申请的内存大小
    size = 0;
    b = c->buffer;

    //如果主请求的请求行长度为0
    if (mr->request_line.len == 0) {
        /* return empty string on invalid request */
        lua_pushlstring(L, "", 0);
        return 1;
    }

    //换行是 CR 还是 CR LF
    if (mr->request_line.data[mr->request_line.len] == CR) {
        line_break_len = 2;

    } else {
        line_break_len = 1;
    }

    //说明请求行在b中
    if (mr->request_line.data >= b->start
        && mr->request_line.data + mr->request_line.len
           + line_break_len <= b->pos)
    {
        first = b;
        size += b->pos - mr->request_line.data;
    }

    dd("size: %d", (int) size);

    if (hc->nbusy) {
#if (nginx_version >= 1011011)
        //首次调用时lmcf->busy_buf_ptr_count==0
        if (hc->nbusy > lmcf->busy_buf_ptr_count) {     //说明本次请求首次调用此函数，否则两个值应该相等
            if (lmcf->busy_buf_ptrs) {
                ngx_free(lmcf->busy_buf_ptrs);
            }

            //nbusy个ngx_buf_t的指针
            lmcf->busy_buf_ptrs = ngx_alloc(hc->nbusy * sizeof(ngx_buf_t *),
                                            r->connection->log);

            if (lmcf->busy_buf_ptrs == NULL) {
                return luaL_error(L, "no memory");
            }

            //设置 lmcf->busy_buf_ptr_count = hc->nbusy
            lmcf->busy_buf_ptr_count = hc->nbusy;
        }

        //初始化bb数组
        bb = lmcf->busy_buf_ptrs;
        for (cl = hc->busy; cl; cl = cl->next) {
            *bb++ = cl->buf;
        }
#endif
        b = NULL;

#if (nginx_version >= 1011011)
        //遍历lmcf->busy_buf_ptrs数组
        bb = lmcf->busy_buf_ptrs;
        for (i = hc->nbusy; i > 0; i--) {
            b = bb[i - 1];
#else
        for (i = 0; i < hc->nbusy; i++) {
            b = hc->busy[i];
#endif

            dd("busy buf: %d: [%.*s]", (int) i, (int) (b->pos - b->start),
               b->start);

            //first为请求行数据所在的buf
            if (first == NULL) {
                if (mr->request_line.data >= b->pos
                    || mr->request_line.data
                       + mr->request_line.len + line_break_len
                       <= b->start)
                {
                    continue;
                }

                dd("found first at %d", (int) i);
                first = b;
            }

            dd("adding size %d", (int) (b->pos - b->start));
            size += b->pos - b->start;
        }
    }

    size++;  /* plus the null terminator, as required by the later
                ngx_strstr() call */

    dd("header size: %d", (int) size);

    //分配size大小的空间
    data = lua_newuserdata(L, size);
    last = data;

    b = c->buffer;
    found = 0;

    if (first == b) {
        found = 1;
        pos = b->pos;

        //如果需要请求行
        if (no_req_line) {
            //跳过请求行开始拷贝
            last = ngx_copy(data,
                            mr->request_line.data
                            + mr->request_line.len + line_break_len,
                            pos - mr->request_line.data
                            - mr->request_line.len - line_break_len);

        } else {
            last = ngx_copy(data, mr->request_line.data,
                            pos - mr->request_line.data);
        }

        if (b != mr->header_in) {
            /* skip truncated header entries (if any) */
            while (last > data && last[-1] != LF && last[-1] != '\0') {
                last--;
            }
        }

        i = 0;
        for (p = data; p != last; p++) {
            if (*p == '\0') {
                i++;
                if (p + 1 != last && *(p + 1) == LF) {
                    *p = CR;

                } else if (i % 2 == 1) {
                    *p = ':';

                } else {
                    *p = LF;
                }
            }
        }
    }

    if (hc->nbusy) {

#if (nginx_version >= 1011011)
        bb = lmcf->busy_buf_ptrs;
        for (i = hc->nbusy - 1; i >= 0; i--) {
            b = bb[i];
#else
        for (i = 0; i < hc->nbusy; i++) {
            b = hc->busy[i];
#endif

            if (!found) {
                if (b != first) {
                    continue;
                }

                dd("found first");
                found = 1;
            }

            p = last;

            pos = b->pos;

            if (b == first) {
                dd("request line: %.*s", (int) mr->request_line.len,
                   mr->request_line.data);

                if (no_req_line) {
                    last = ngx_copy(last,
                                    mr->request_line.data
                                    + mr->request_line.len + line_break_len,
                                    pos - mr->request_line.data
                                    - mr->request_line.len - line_break_len);

                } else {
                    last = ngx_copy(last,
                                    mr->request_line.data,
                                    pos - mr->request_line.data);

                }

            } else {
                //复制整个buf
                last = ngx_copy(last, b->start, pos - b->start);
            }

#if 1
            /* skip truncated header entries (if any) */
            while (last > p && last[-1] != LF && last[-1] != '\0') {
                last--;
            }
#endif

            j = 0;
            for (; p != last; p++) {
                if (*p == '\0') {
                    j++;
                    if (p + 1 == last) {
                        *p = LF;

                    } else if (*(p + 1) == LF) {
                        *p = CR;

                    } else if (j % 2 == 1) {
                        *p = ':';

                    } else {
                        *p = LF;
                    }
                }
            }

            if (b == mr->header_in) {
                break;
            }
        }
    }

    *last++ = '\0';

    if (last - data > (ssize_t) size) {
        return luaL_error(L, "buffer error: %d", (int) (last - data - size));
    }

    /* strip the leading part (if any) of the request body in our header.
     * the first part of the request body could slip in because nginx core's
     * ngx_http_request_body_length_filter and etc can move r->header_in->pos
     * in case that some of the body data has been preread into r->header_in.
     */

    if ((p = (u_char *) ngx_strstr(data, CRLF CRLF)) != NULL) {
        last = p + sizeof(CRLF CRLF) - 1;

    } else if ((p = (u_char *) ngx_strstr(data, CRLF "\n")) != NULL) {
        last = p + sizeof(CRLF "\n") - 1;

    } else if ((p = (u_char *) ngx_strstr(data, "\n" CRLF)) != NULL) {
        last = p + sizeof("\n" CRLF) - 1;

    } else {
        for (p = last - 1; p - data >= 2; p--) {
            if (p[0] == LF && p[-1] == CR) {
                p[-1] = LF;
                last = p + 1;
                break;
            }

            if (p[0] == LF && p[-1] == LF) {
                last = p + 1;
                break;
            }
        }
    }

    //重新复制一份到栈里
    lua_pushlstring(L, (char *) data, last - data);
    return 1;
}


/**
 * api ngx.resp.get_headers
 * 
 * syntax: headers = ngx.resp.get_headers(max_headers?, raw?)
 * 
 * raw: 是否将header name转为小写
 */
static int
ngx_http_lua_ngx_resp_get_headers(lua_State *L)
{
    ngx_list_part_t    *part;
    ngx_table_elt_t    *header;
    ngx_http_request_t *r;
    ngx_http_lua_ctx_t *ctx;
    u_char             *lowcase_key = NULL;
    size_t              lowcase_key_sz = 0;
    ngx_uint_t          i;
    int                 n;
    int                 max;
    int                 raw = 0;
    int                 count = 0;
    int                 truncated = 0;
    int                 extra = 0;
    u_char             *p = NULL;
    size_t              len = 0;

    n = lua_gettop(L);

    if (n >= 1) {
        if (lua_isnil(L, 1)) {
            max = NGX_HTTP_LUA_MAX_HEADERS;

        } else {
            max = luaL_checkinteger(L, 1);      //最多返回的header数量。默认为100
        }

        if (n >= 2) {
            raw = lua_toboolean(L, 2);          //是否将header名称转为小写返回。默认为false 
        }

    } else {
        max = NGX_HTTP_LUA_MAX_HEADERS;
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    ngx_http_lua_check_fake_request(L, r);

    //遍历所有响应头，计算响应头数量
    part = &r->headers_out.headers.part;
    count = part->nelts;
    while (part->next != NULL) {
        part = part->next;
        count += part->nelts;
    }

    //创建一张count+2个元素的表
    lua_createtable(L, 0, count + 2);

    if (!raw) {     //如果要将header的key转为小写
        lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                              headers_metatable_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_setmetatable(L, -2);
    }

#if 1
    //向返回的表中添加content-type头
    if (r->headers_out.content_type.len) {
        extra++;
        lua_pushliteral(L, "content-type");
        lua_pushlstring(L, (char *) r->headers_out.content_type.data,
                        r->headers_out.content_type.len);
        lua_rawset(L, -3);
    }

    //向返回的表中添加content-length头
    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        extra++;
        lua_pushliteral(L, "content-length");
        if (r->headers_out.content_length_n > NGX_MAX_INT32_VALUE) {
            p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
            if (p == NULL) {
                return luaL_error(L, "no memory");
            }

            len = ngx_snprintf(p, NGX_OFF_T_LEN, "%O",
                               r->headers_out.content_length_n) - p;

            lua_pushlstring(L, (char *) p, len);

        } else {
            lua_pushfstring(L, "%d", (int) r->headers_out.content_length_n);
        }

        lua_rawset(L, -3);
    }

    //向返回的表中添加connection头
    extra++;
    lua_pushliteral(L, "connection");
    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        lua_pushliteral(L, "upgrade");

    } else if (r->keepalive) {
        lua_pushliteral(L, "keep-alive");

    } else {
        lua_pushliteral(L, "close");
    }

    lua_rawset(L, -3);

    //向返回的表中添加transfer-encoding头
    if (r->chunked) {
        extra++;
        lua_pushliteral(L, "transfer-encoding");
        lua_pushliteral(L, "chunked");
        lua_rawset(L, -3);
    }
#endif

    //计算剩余的还能返回的header数量，标记truncated
    if (max > 0 && count + extra > max) {
        truncated = 1;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua exceeding response header limit %d > %d",
                       count + extra, max);
        count = max - extra;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    //遍历所有响应头，将其加入到返回的表中
    for (i = 0; /* void */; i++) {

        dd("stack top: %d", lua_gettop(L));

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        //忽略要删除的heaer
        if (header[i].hash == 0) {
            continue;
        }

        if (raw) {
            lua_pushlstring(L, (char *) header[i].key.data, header[i].key.len);

        } else {
            /* nginx does not even bother initializing output header entry's
             * "lowcase_key" field. so we cannot count on that at all. */
            if (header[i].key.len > lowcase_key_sz) {
                lowcase_key_sz = header[i].key.len * 2;

                /* we allocate via Lua's GC to prevent in-request
                 * leaks in the nginx request memory pools */
                lowcase_key = lua_newuserdata(L, lowcase_key_sz);
                lua_insert(L, 1);
            }

            ngx_strlow(lowcase_key, header[i].key.data, header[i].key.len);
            lua_pushlstring(L, (char *) lowcase_key, header[i].key.len);
        }

        /* stack: [udata] table key */

        lua_pushlstring(L, (char *) header[i].value.data,
                        header[i].value.len); /* stack: [udata] table key
                                                 value */

        ngx_http_lua_set_multi_value_table(L, -3);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua response header: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        if (--count <= 0) {
            break;
        }
    }  /* for */

    if (truncated) {
        lua_pushliteral(L, "truncated");
        return 2;
    }

    return 1;
}


static int
ngx_http_lua_ngx_req_header_set(lua_State *L)
{
    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting two arguments, but seen %d",
                          lua_gettop(L));
    }

    return ngx_http_lua_ngx_req_header_set_helper(L);
}


static int
ngx_http_lua_ngx_req_header_set_helper(lua_State *L)
{
    ngx_http_request_t          *r;
    u_char                      *p;
    ngx_str_t                    key;
    ngx_str_t                    value;
    ngx_uint_t                   i;
    size_t                       len;
    ngx_int_t                    rc;
    ngx_uint_t                   n;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ngx_http_lua_check_fake_request(L, r);

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return 0;
    }

    p = (u_char *) luaL_checklstring(L, 1, &len);

    dd("key: %.*s, len %d", (int) len, p, (int) len);

#if 0
    /* replace "_" with "-" */
    for (i = 0; i < len; i++) {
        if (p[i] == '_') {
            p[i] = '-';
        }
    }
#endif

    key.data = ngx_palloc(r->pool, len + 1);
    if (key.data == NULL) {
        return luaL_error(L, "no memory");
    }

    ngx_memcpy(key.data, p, len);

    key.data[len] = '\0';

    key.len = len;

    if (lua_type(L, 2) == LUA_TNIL) {
        ngx_str_null(&value);

    } else if (lua_type(L, 2) == LUA_TTABLE) {
        n = lua_objlen(L, 2);
        if (n == 0) {
            ngx_str_null(&value);

        } else {
            for (i = 1; i <= n; i++) {
                dd("header value table index %d, top: %d", (int) i,
                   lua_gettop(L));

                lua_rawgeti(L, 2, i);
                p = (u_char *) luaL_checklstring(L, -1, &len);

                /*
                 * we also copy the trailing '\0' char here because nginx
                 * header values must be null-terminated
                 * */

                value.data = ngx_palloc(r->pool, len + 1);
                if (value.data == NULL) {
                    return luaL_error(L, "no memory");
                }

                ngx_memcpy(value.data, p, len + 1);
                value.len = len;

                rc = ngx_http_lua_set_input_header(r, key, value,
                                                   i == 1 /* override */);

                if (rc == NGX_ERROR) {
                    return luaL_error(L,
                                      "failed to set header %s (error: %d)",
                                      key.data, (int) rc);
                }
            }

            return 0;
        }

    } else {

        /*
         * we also copy the trailing '\0' char here because nginx
         * header values must be null-terminated
         * */

        p = (u_char *) luaL_checklstring(L, 2, &len);
        value.data = ngx_palloc(r->pool, len + 1);
        if (value.data == NULL) {
            return luaL_error(L, "no memory");
        }

        ngx_memcpy(value.data, p, len + 1);
        value.len = len;
    }

    dd("key: %.*s, value: %.*s",
       (int) key.len, key.data, (int) value.len, value.data);

    rc = ngx_http_lua_set_input_header(r, key, value, 1 /* override */);

    if (rc == NGX_ERROR) {
        return luaL_error(L, "failed to set header %s (error: %d)",
                          key.data, (int) rc);
    }

    return 0;
}


/**
 * ngx_http_lua_inject_ngx_api->.
 * 
 * 注入ngx ngx.req.get_headers ngx.resp.get_headers 相关元表方法
 */
void
ngx_http_lua_create_headers_metatable(ngx_log_t *log, lua_State *L)
{
    int rc;
    const char buf[] =
        "local tb, key = ...\n"
        "local new_key = string.gsub(string.lower(key), '_', '-')\n"
        "if new_key ~= key then return tb[new_key] else return nil end";

    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                          headers_metatable_key));

    /* metatable for ngx.req.get_headers(_, true) and
     * ngx.resp.get_headers(_, true) */
    lua_createtable(L, 0, 1);

    rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=headers metatable");
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to load Lua code for the metamethod for "
                      "headers: %i: %s", rc, lua_tostring(L, -1));

        lua_pop(L, 3);
        return;
    }

    lua_setfield(L, -2, "__index");
    lua_rawset(L, LUA_REGISTRYINDEX);
}


/**
 * ngx.req.get_headers 方法使用
 * 获取headers 数量
 */
int
ngx_http_lua_ffi_req_get_headers_count(ngx_http_request_t *r, int max,
    int *truncated)
{
    int                           count;
    ngx_list_part_t              *part;
#if (NGX_HTTP_V3)
    int                           has_host = 0;
    ngx_uint_t                    i;
    ngx_table_elt_t              *header;
#endif

    //fake request
    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    *truncated = 0;

    if (max < 0) {
        max = NGX_HTTP_LUA_MAX_HEADERS;
    }

    //遍历r->headers_in.headers 动态数组
    part = &r->headers_in.headers.part;

#if (NGX_HTTP_V3)
    count = 0;
    header = part->elts;

    if (r->http_version == NGX_HTTP_VERSION_30
        && r->headers_in.server.data != NULL)
    {
        has_host = 1;
        count++;
    }

    if (has_host == 1) {
        for (i = 0; /* void */; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (header[i].key.len == 4
                && ngx_strncasecmp(header[i].key.data,
                                   (u_char *) "host", 4) == 0)
            {
                continue;
            }

            count++;
        }

    } else {
        count = part->nelts;
        while (part->next != NULL) {
            part = part->next;
            count += part->nelts;
        }
    }
#else
    count = part->nelts;
    while (part->next != NULL) {
        part = part->next;
        count += part->nelts;
    }
#endif

    //如果请求头数量超过max, 将count置为max， 且truncated置1
    if (max > 0 && count > max) {
        *truncated = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua exceeding request header limit %d > %d", count,
                       max);
        count = max;
    }

    return count;
}


/**
 * 获取请求头 ngx.req.get_headers()
 * out: 输出kv对
 * count: 
 */
int
ngx_http_lua_ffi_req_get_headers(ngx_http_request_t *r,
    ngx_http_lua_ffi_table_elt_t *out, int count, int raw)
{
    int                           n;
    ngx_uint_t                    i;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
#if (NGX_HTTP_V3)
    int                           has_host = 0;
#endif

    if (count <= 0) {
        return NGX_OK;
    }

    n = 0;

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30
        && r->headers_in.server.data != NULL)
    {
        out[n].key.data = (u_char *) "host";
        out[n].key.len = sizeof("host") - 1;
        out[n].value.len = r->headers_in.server.len;
        out[n].value.data = r->headers_in.server.data;
        has_host = 1;
        ++n;
    }
#endif

    //遍历所有请求头
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

#if (NGX_HTTP_V3)
        if (has_host == 1 && header[i].key.len == 4
            && ngx_strncasecmp(header[i].key.data, (u_char *) "host", 4) == 0)
        {
            continue;
        }
#endif

        if (raw) {
            //原始key
            out[n].key.data = header[i].key.data;
            out[n].key.len = (int) header[i].key.len;

        } else {
            //小写的key
            out[n].key.data = header[i].lowcase_key;
            out[n].key.len = (int) header[i].key.len;
        }

        out[n].value.data = header[i].value.data;
        out[n].value.len = (int) header[i].value.len;

        if (++n == count) {
            return NGX_OK;
        }
    }

    return NGX_OK;
}


/**
 * 设置响应头 ngx.header.HEADER='xxx'
 * key_data:
 * key_len:
 * is_nil: 是否将值设值为nil , 即是否是要清空响应头
 * sval:
 * sval_len:
 * mvals: 表示设置了多个值，mvals为指向多个值的数组的指针
 * mvals_len: 值的数量
 * override:
 * errmsg:
 * 
 * 
 */
int
ngx_http_lua_ffi_set_resp_header(ngx_http_request_t *r, const u_char *key_data,
    size_t key_len, int is_nil, const u_char *sval, size_t sval_len,
    ngx_http_lua_ffi_str_t *mvals, size_t mvals_len, int override,
    char **errmsg)
{
    u_char                      *p;
    ngx_str_t                    value, key;
    ngx_uint_t                   i;
    size_t                       len;
    ngx_http_lua_ctx_t          *ctx;
    ngx_int_t                    rc;
    ngx_http_lua_loc_conf_t     *llcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    //fake request
    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    //如果响应头已经发出，不允许重新设置
    if (r->header_sent || ctx->header_sent) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "attempt to "
                      "set ngx.header.HEADER after sending out "
                      "response headers");
        return NGX_DECLINED;
    }

    //为key申请新的空间
    key.data = ngx_palloc(r->pool, key_len + 1);
    if (key.data == NULL) {
        goto nomem;
    }

    ngx_memcpy(key.data, key_data, key_len);
    key.data[key_len] = '\0';
    key.len = key_len;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    //如果需要将key中的下划线转为中划线
    if (llcf->transform_underscores_in_resp_headers) {
        /* replace "_" with "-" */
        p = key.data;
        for (i = 0; i < key_len; i++) {
            if (p[i] == '_') {
                p[i] = '-';
            }
        }
    }

    //标识用户重新设置了响应头
    ctx->headers_set = 1;

    if (is_nil) {
        //如果是要清空响应头
        value.data = NULL;
        value.len = 0;

    } else if (mvals) {

        if (mvals_len == 0) {
            value.data = NULL;
            value.len = 0;

        } else {
            //设置了多个值，遍历每个值
            for (i = 0; i < mvals_len; i++) {
                dd("header value table index %d", (int) i);

                p = mvals[i].data;
                len = mvals[i].len;

                value.data = ngx_palloc(r->pool, len);
                if (value.data == NULL) {
                    goto nomem;
                }

                ngx_memcpy(value.data, p, len);
                value.len = len;

                rc = ngx_http_lua_set_output_header(r, ctx, key, value,
                                                    override && i == 0);

                if (rc == NGX_ERROR) {
                    *errmsg = "failed to set header";
                    return NGX_ERROR;
                }
            }

            return NGX_OK;
        }

    } else {
        p = (u_char *) sval;
        value.data = ngx_palloc(r->pool, sval_len);
        if (value.data == NULL) {
            goto nomem;
        }

        ngx_memcpy(value.data, p, sval_len);
        value.len = sval_len;
    }

    dd("key: %.*s, value: %.*s",
       (int) key.len, key.data, (int) value.len, value.data);

    rc = ngx_http_lua_set_output_header(r, ctx, key, value, override);

    if (rc == NGX_ERROR) {
        *errmsg = "failed to set header";
        return NGX_ERROR;
    }

    return 0;

nomem:

    *errmsg = "no memory";
    return NGX_ERROR;
}


/**
 * ngx.req.set_header
 * 
 * syntax: ngx.req.set_header(header_name, header_value)
 * 
 * key:
 * key_len:
 * value:
 * value_len
 * mvals:
 * mvals_len:
 * override:
 * errmsg:
 * 
 */
int
ngx_http_lua_ffi_req_set_header(ngx_http_request_t *r, const u_char *key,
    size_t key_len, const u_char *value, size_t value_len,
    ngx_http_lua_ffi_str_t *mvals, size_t mvals_len, int override,
    char **errmsg)
{
    u_char                      *p;
    size_t                       len;
    ngx_uint_t                   i;
    ngx_str_t                    k, v;

    if (r->connection->fd == (ngx_socket_t) -1) {  /* fake request */
        return NGX_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_DECLINED;
    }

    //复制key
    k.data = ngx_palloc(r->pool, key_len + 1);
    if (k.data == NULL) {
        goto nomem;
    }

    ngx_memcpy(k.data, key, key_len);
    k.data[key_len] = '\0';
    k.len = key_len;

    if (mvals) {
        // value为多个值
        if (mvals_len > 0) {
            //遍历value的多个值
            for (i = 0; i < mvals_len; i++) {
                p = mvals[i].data;
                len = mvals[i].len;

                v.data = ngx_palloc(r->pool, len + 1);
                if (v.data == NULL) {
                    goto nomem;
                }

                ngx_memcpy(v.data, p, len);
                v.data[len] = '\0';
                v.len = len;

                //调用单个header的设置方法。里边会遍历r->headers查找同名的header
                if (ngx_http_lua_set_input_header(r, k, v, override && i == 0)
                    != NGX_OK)
                {
                    goto failed;
                }
            }

            return NGX_OK;
        }

        v.data = NULL;
        v.len = 0;

    } else if (value) {
        //设置单个值
        v.data = ngx_palloc(r->pool, value_len + 1);
        if (v.data == NULL) {
            goto nomem;
        }

        ngx_memcpy(v.data, value, value_len);
        v.data[value_len] = '\0';
        v.len = value_len;

    } else {
        v.data = NULL;
        v.len = 0;
    }

    if (ngx_http_lua_set_input_header(r, k, v, override) != NGX_OK) {
        goto failed;
    }

    return NGX_OK;

nomem:

    *errmsg = "no memory";
    return NGX_ERROR;

failed:

    *errmsg = "failed to set header";
    return NGX_ERROR;
}


/**
 * 读取ngx.header.HEADER
 * key: key
 * key_len: key_len
 * key_buf：新的用于存放key的buf. （key在本方法中可能被改写，而传入的*key可能是不能被修改的）
 * values: 出参。用于存放value的数组，数组个数为 max_nvalues
 * max_nvalues:最大读取的header的value的个数，默认值100
 */
int
ngx_http_lua_ffi_get_resp_header(ngx_http_request_t *r,
    const u_char *key, size_t key_len,
    u_char *key_buf, ngx_http_lua_ffi_str_t *values, int max_nvalues,
    char **errmsg)
{
    int                  found;
    u_char               c, *p;
    time_t               last_modified;
    ngx_uint_t           i;
    ngx_table_elt_t     *h;
    ngx_list_part_t     *part;
    ngx_http_lua_ctx_t  *ctx;

    ngx_http_lua_loc_conf_t     *llcf;

    //fake request
    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        *errmsg = "no ctx found";
        return NGX_ERROR;
    }

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
    //是否将header name中的_替换为-
    if (llcf->transform_underscores_in_resp_headers
        && memchr(key, '_', key_len) != NULL)
    {
        for (i = 0; i < key_len; i++) {
            c = key[i];
            if (c == '_') {
                c = '-';
            }

            //如果要修改的话，复制一份到key_buf中
            key_buf[i] = c;
        }

    } else {
        //无需修改，直接将key_buf指向key
        key_buf = (u_char *) key;
    }

    //对于几个常见的请求头，Content-Length/Content-Type/Last-Modified 直接设置返回值
    switch (key_len) {
    case 14:
        //如果key是Content-Length
        if (r->headers_out.content_length == NULL
            && r->headers_out.content_length_n >= 0
            && ngx_strncasecmp(key_buf, (u_char *) "Content-Length", 14) == 0)
        {
            p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
            if (p == NULL) {
                *errmsg = "no memory";
                return NGX_ERROR;
            }

            //设置返回参数
            values[0].data = p;
            values[0].len = (int) (ngx_snprintf(p, NGX_OFF_T_LEN, "%O",
                                              r->headers_out.content_length_n)
                            - p);
            return 1;
        }

        break;

    case 12:
        //如果key是Content-Type
        if (ngx_strncasecmp(key_buf, (u_char *) "Content-Type", 12) == 0
            && r->headers_out.content_type.len)
        {
            //设置返回参数
            values[0].data = r->headers_out.content_type.data;
            values[0].len = r->headers_out.content_type.len;
            return 1;
        }

        break;

    case 13:
        //如果key是Last-Modified
        if (ngx_strncasecmp(key_buf, (u_char *) "Last-Modified", 13) == 0) {
            last_modified = r->headers_out.last_modified_time;
            if (last_modified >= 0) {
                p = ngx_palloc(r->pool,
                               sizeof("Mon, 28 Sep 1970 06:00:00 GMT"));
                if (p == NULL) {
                    *errmsg = "no memory";
                    return NGX_ERROR;
                }

                //设置返回参数
                values[0].data = p;
                values[0].len = ngx_http_time(p, last_modified) - p;

                return 1;
            }

            return 0;
        }

        break;

    default:
        break;
    }

    dd("not a built-in output header");

#if 1
    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        /* XXX ngx_http_core_find_config_phase, for example,
         * may not initialize the "key" and "hash" fields
         * for a nasty optimization purpose, and
         * we have to work-around it here */

        r->headers_out.location->hash = ngx_http_lua_location_hash;
        ngx_str_set(&r->headers_out.location->key, "Location");
    }
#endif

    found = 0;

    //遍历响应头
    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        //跳过hash为0的响应头
        if (h[i].hash == 0) {
            continue;
        }

        dd("checking (%d) \"%.*s\"", (int) h[i].key.len, (int) h[i].key.len,
           h[i].key.data);

        //根据key查找header
        if (h[i].key.len == key_len
            && ngx_strncasecmp(key_buf, h[i].key.data, key_len) == 0)
        {
            //如果找到
            values[found].data = h[i].value.data;
            values[found].len = (int) h[i].value.len;

            //达到最大的返回值数量
            if (++found >= max_nvalues) {
                break;
            }
        }
    }

    return found;
}


/**
 * 添加在cf->pool上的清理函数
 */
#if (nginx_version >= 1011011)
void
ngx_http_lua_ngx_raw_header_cleanup(void *data)
{
    ngx_http_lua_main_conf_t  *lmcf;

    lmcf = (ngx_http_lua_main_conf_t *) data;

    if (lmcf->busy_buf_ptrs) {
        ngx_free(lmcf->busy_buf_ptrs);
        lmcf->busy_buf_ptrs = NULL;
    }
}
#endif


#if (NGX_DARWIN)
int
ngx_http_lua_ffi_set_resp_header_macos(ngx_http_lua_set_resp_header_params_t *p)
{
    return ngx_http_lua_ffi_set_resp_header(p->r, (const u_char *) p->key_data,
                                            p->key_len, p->is_nil,
                                            (const u_char *) p->sval,
                                            p->sval_len,
                                            p->mvals, p->mvals_len,
                                            p->override, p->errmsg);
}
#endif


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
