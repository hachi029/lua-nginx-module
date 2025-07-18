
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <nginx.h>
#include "ngx_http_lua_headers_in.h"
#include "ngx_http_lua_util.h"
#include <ctype.h>


static ngx_int_t ngx_http_set_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_header_helper(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value,
    ngx_table_elt_t **output_header);
static ngx_int_t ngx_http_set_builtin_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_user_agent_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_connection_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_content_length_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_builtin_multi_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_clear_builtin_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_clear_content_length_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_lua_validate_host(ngx_str_t *host, ngx_pool_t *pool,
    ngx_uint_t alloc);
static ngx_int_t ngx_http_set_host_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_lua_rm_header_helper(ngx_list_t *l,
    ngx_list_part_t *cur, ngx_uint_t i);


static ngx_http_lua_set_header_t  ngx_http_lua_set_handlers[] = {
    { ngx_string("Host"),
                 offsetof(ngx_http_headers_in_t, host),
                 ngx_http_set_host_header },

    { ngx_string("Connection"),
                 offsetof(ngx_http_headers_in_t, connection),
                 ngx_http_set_connection_header },

    { ngx_string("If-Modified-Since"),
                 offsetof(ngx_http_headers_in_t, if_modified_since),
                 ngx_http_set_builtin_header },

    { ngx_string("If-Unmodified-Since"),
                 offsetof(ngx_http_headers_in_t, if_unmodified_since),
                 ngx_http_set_builtin_header },

    { ngx_string("If-Match"),
                 offsetof(ngx_http_headers_in_t, if_match),
                 ngx_http_set_builtin_header },

    { ngx_string("If-None-Match"),
                 offsetof(ngx_http_headers_in_t, if_none_match),
                 ngx_http_set_builtin_header },

    { ngx_string("User-Agent"),
                 offsetof(ngx_http_headers_in_t, user_agent),
                 ngx_http_set_user_agent_header },

    { ngx_string("Referer"),
                 offsetof(ngx_http_headers_in_t, referer),
                 ngx_http_set_builtin_header },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_in_t, content_length),
                 ngx_http_set_content_length_header },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_in_t, content_type),
                 ngx_http_set_builtin_header },

    { ngx_string("Range"),
                 offsetof(ngx_http_headers_in_t, range),
                 ngx_http_set_builtin_header },

    { ngx_string("If-Range"),
                 offsetof(ngx_http_headers_in_t, if_range),
                 ngx_http_set_builtin_header },

    { ngx_string("Transfer-Encoding"),
                 offsetof(ngx_http_headers_in_t, transfer_encoding),
                 ngx_http_set_builtin_header },

    { ngx_string("Expect"),
                 offsetof(ngx_http_headers_in_t, expect),
                 ngx_http_set_builtin_header },

    { ngx_string("Upgrade"),
                 offsetof(ngx_http_headers_in_t, upgrade),
                 ngx_http_set_builtin_header },

#if (NGX_HTTP_GZIP)
    { ngx_string("Accept-Encoding"),
                 offsetof(ngx_http_headers_in_t, accept_encoding),
                 ngx_http_set_builtin_header },

    { ngx_string("Via"),
                 offsetof(ngx_http_headers_in_t, via),
                 ngx_http_set_builtin_header },
#endif

    { ngx_string("Authorization"),
                 offsetof(ngx_http_headers_in_t, authorization),
                 ngx_http_set_builtin_header },

    { ngx_string("Keep-Alive"),
                 offsetof(ngx_http_headers_in_t, keep_alive),
                 ngx_http_set_builtin_header },

#if (NGX_HTTP_X_FORWARDED_FOR)
    { ngx_string("X-Forwarded-For"),
                 offsetof(ngx_http_headers_in_t, x_forwarded_for),
                 ngx_http_set_builtin_multi_header },

#endif

#if (NGX_HTTP_REALIP)
    { ngx_string("X-Real-IP"),
                 offsetof(ngx_http_headers_in_t, x_real_ip),
                 ngx_http_set_builtin_header },
#endif

#if (NGX_HTTP_DAV)
    { ngx_string("Depth"),
                 offsetof(ngx_http_headers_in_t, depth),
                 ngx_http_set_builtin_header },

    { ngx_string("Destination"),
                 offsetof(ngx_http_headers_in_t, destination),
                 ngx_http_set_builtin_header },

    { ngx_string("Overwrite"),
                 offsetof(ngx_http_headers_in_t, overwrite),
                 ngx_http_set_builtin_header },

    { ngx_string("Date"), offsetof(ngx_http_headers_in_t, date),
                 ngx_http_set_builtin_header },
#endif

#if defined(nginx_version) && nginx_version >= 1023000
    { ngx_string("Cookie"),
                 offsetof(ngx_http_headers_in_t, cookie),
                 ngx_http_set_builtin_multi_header },
#else
    { ngx_string("Cookie"),
                 offsetof(ngx_http_headers_in_t, cookies),
                 ngx_http_set_builtin_multi_header },
#endif

    { ngx_null_string, 0, ngx_http_set_header }
};


/**
 * 通用的设置请求头的方法
 */
/* request time implementation */

static ngx_int_t
ngx_http_set_header(ngx_http_request_t *r, ngx_http_lua_header_val_t *hv,
    ngx_str_t *value)
{
    return ngx_http_set_header_helper(r, hv, value, NULL);
}


/**
 * 设置请求header的一个辅助方法
 * 
 * 
 * value: header值
 * output_header: 出参，指向实际设置的header
 * 
 */
static ngx_int_t
ngx_http_set_header_helper(ngx_http_request_t *r, ngx_http_lua_header_val_t *hv,
    ngx_str_t *value, ngx_table_elt_t **output_header)
{
    ngx_table_elt_t             *h, *matched;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    ngx_uint_t                   rc;

    //表示不要覆盖已有的同名header
    if (hv->no_override) {
        //添加一个新的header
        goto new_header;
    }

    matched = NULL;

retry:

    //遍历所有的header动态数组 r->headers_in.headers， 查找是否有同名的
    part = &r->headers_in.headers.part;
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

        dd("i: %d, part: %p", (int) i, part);

        if (h[i].key.len == hv->key.len
            && ngx_strncasecmp(h[i].key.data, hv->key.data, h[i].key.len)
               == 0)
        {
            //找到同名的heade了, value->len==0表示要移除这个header
            if (value->len == 0 || (matched && matched != &h[i])) {
                //将其hash设为0
                h[i].hash = 0;

                dd("rm header %.*s: %.*s", (int) h[i].key.len, h[i].key.data,
                   (int) h[i].value.len, h[i].value.data);

                //移除header
                rc = ngx_http_lua_rm_header_helper(&r->headers_in.headers,
                                                   part, i);

                ngx_http_lua_assert(!(r->headers_in.headers.part.next == NULL
                                      && r->headers_in.headers.last
                                         != &r->headers_in.headers.part));

                dd("rm header: rc=%d", (int) rc);

                if (rc == NGX_OK) {

                    if (output_header) {
                        *output_header = NULL;
                    }

                    goto retry;
                }

                return NGX_ERROR;
            }

            //设置值。h[i]为r->headers_in中的元素
            h[i].value = *value;

            if (output_header) {
                *output_header = &h[i];
                dd("setting existing builtin input header");
            }

            if (matched == NULL) {
                matched = &h[i];
            }
        }
    }

    //找到了同名的header
    if (matched){
        return NGX_OK;
    }
    /** 没找到同名的header, 表示要添加一个新的header */

    //表示要移除这个header, 什么也无需做
    if (value->len == 0) {
        return NGX_OK;
    }

new_header:

    //r->headers_in.headers 中添加一个元素
    h = ngx_list_push(&r->headers_in.headers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    dd("created new header for %.*s", (int) hv->key.len, hv->key.data);

    if (value->len == 0) {
        h->hash = 0;

    } else {
        //设置hash
        h->hash = hv->hash;
    }

    //设置key和value
    h->key = hv->key;
    h->value = *value;
#if defined(nginx_version) && nginx_version >= 1023000
    h->next = NULL;
#endif

    //设置lowcase_key
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (output_header) {
        *output_header = h;
    }

    return NGX_OK;
}


/**
 * 将value设置到r->headers_in对应的属性上
 */
static ngx_int_t
ngx_http_set_builtin_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
    ngx_table_elt_t             *h, **old;

    dd("entered set_builtin_header (input)");

    if (hv->offset) {
        //根据offset找到属性位置
        old = (ngx_table_elt_t **) ((char *) &r->headers_in + hv->offset);

    } else {
        old = NULL;
    }

    dd("old builtin ptr ptr: %p", old);
    if (old) {
        dd("old builtin ptr: %p", *old);
    }

    if (old == NULL || *old == NULL) {
        dd("set normal header");
        return ngx_http_set_header_helper(r, hv, value, old);
    }

    h = *old;

    if (value->len == 0) {
        h->hash = 0;
        h->value = *value;

        return ngx_http_set_header_helper(r, hv, value, old);
    }

    h->hash = hv->hash;
    h->value = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest,
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NGX_DECLINED;
            }

            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NGX_DECLINED;

        default:

            if (ngx_path_separator(ch)) {
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    if (alloc) {
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}


/**
 * 当复制主请求header到子请求时，对Host请求头进行额外处理
 */
static ngx_int_t
ngx_http_set_host_header(ngx_http_request_t *r, ngx_http_lua_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_str_t                    host;
    ngx_http_lua_main_conf_t    *lmcf;
    ngx_http_variable_value_t   *var;

    dd("server new value len: %d", (int) value->len);

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

    if (value->len) {
        host= *value;

        //校验请求Host
        if (ngx_http_lua_validate_host(&host, r->pool, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        //设置host到server
        r->headers_in.server = host;

    } else {
        r->headers_in.server = *value;
    }

    //将$host置为无效
    var = &r->variables[lmcf->host_var_index];
    var->valid = 0;
    var->not_found = 0;

    return ngx_http_set_builtin_header(r, hv, value);
}


static ngx_int_t
ngx_http_set_connection_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
    r->headers_in.connection_type = 0;

    if (value->len == 0) {
        return ngx_http_set_builtin_header(r, hv, value);
    }

    if (ngx_strcasestrn(value->data, "close", 5 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;
        r->headers_in.keep_alive_n = -1;

    } else if (ngx_strcasestrn(value->data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return ngx_http_set_builtin_header(r, hv, value);
}


/* borrowed the code from ngx_http_request.c:ngx_http_process_user_agent */
static ngx_int_t
ngx_http_set_user_agent_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
    u_char  *user_agent, *msie;

    /* clear existing settings */

    r->headers_in.msie = 0;
    r->headers_in.msie6 = 0;
    r->headers_in.opera = 0;
    r->headers_in.gecko = 0;
    r->headers_in.chrome = 0;
    r->headers_in.safari = 0;
    r->headers_in.konqueror = 0;

    if (value->len == 0) {
        return ngx_http_set_builtin_header(r, hv, value);
    }

    /* check some widespread browsers */

    user_agent = value->data;

    msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + value->len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }
    }

    if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
                   && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return ngx_http_set_builtin_header(r, hv, value);
}


/**
 * 设置请求头 content_length
 */
static ngx_int_t
ngx_http_set_content_length_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
    off_t           len;

    if (value->len == 0) {
        return ngx_http_clear_content_length_header(r, hv, value);
    }

    len = ngx_atoof(value->data, value->len);
    if (len == NGX_ERROR) {
        return NGX_ERROR;
    }

    dd("reset headers_in.content_length_n to %d", (int) len);

    r->headers_in.content_length_n = len;

    return ngx_http_set_builtin_header(r, hv, value);
}


static ngx_int_t
ngx_http_set_builtin_multi_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
#if defined(nginx_version) && nginx_version >= 1023000
    ngx_table_elt_t  **headers, **ph, *h;

    headers = (ngx_table_elt_t **) ((char *) &r->headers_in + hv->offset);

    if (!hv->no_override && *headers != NULL) {
#if defined(DDEBUG) && (DDEBUG)
        int  nelts = 0;

        for (h = *headers; h; h = h->next) {
            nelts++;
        }

        dd("clear multi-value headers: %d", nelts);
#endif

        *headers = NULL;
    }

    if (ngx_http_set_header_helper(r, hv, value, &h) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (value->len == 0) {
        return NGX_OK;
    }

    dd("new multi-value header: %p", h);

    if (*headers) {
        for (ph = headers; *ph; ph = &(*ph)->next) { /* void */ }
        *ph = h;

    } else {
        *headers = h;
    }

    h->next = NULL;

    return NGX_OK;
#else
    ngx_array_t       *headers;
    ngx_table_elt_t  **v, *h;

    headers = (ngx_array_t *) ((char *) &r->headers_in + hv->offset);

    if (!hv->no_override && headers->nelts > 0) {
        ngx_array_destroy(headers);

        if (ngx_array_init(headers, r->pool, 2,
                           sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        dd("clear multi-value headers: %d", (int) headers->nelts);
    }

#if 1
    if (headers->nalloc == 0) {
        if (ngx_array_init(headers, r->pool, 2,
                           sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
#endif

    if (ngx_http_set_header_helper(r, hv, value, &h) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (value->len == 0) {
        return NGX_OK;
    }

    dd("new multi-value header: %p", h);

    v = ngx_array_push(headers);
    if (v == NULL) {
        return NGX_ERROR;
    }

    *v = h;
    return NGX_OK;
#endif
}


static ngx_int_t
ngx_http_clear_content_length_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
    r->headers_in.content_length_n = -1;

    return ngx_http_clear_builtin_header(r, hv, value);
}


static ngx_int_t
ngx_http_clear_builtin_header(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value)
{
    value->len = 0;
    return ngx_http_set_builtin_header(r, hv, value);
}


/**
 * 1.将key和value都进行uri转义
 * 2.查找ngx_http_lua_set_handlers数组中定义的handler，对此header进行额外的处理
 */
ngx_int_t
ngx_http_lua_set_input_header(ngx_http_request_t *r, ngx_str_t key,
    ngx_str_t value, unsigned override)
{
    ngx_http_lua_header_val_t         hv;
    ngx_http_lua_set_header_t        *handlers = ngx_http_lua_set_handlers;
    ngx_int_t                         rc;
    ngx_uint_t                        i;

    dd("set header value: %.*s", (int) value.len, value.data);

    //对key进行uri转码，如果含有需要转义的字符，会将原值复制后再转义
    rc = ngx_http_lua_copy_escaped_header(r, &key, 1);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    //对value进行uri转码
    rc = ngx_http_lua_copy_escaped_header(r, &value, 0);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (value.len > 0) {
        //key小写后的hash
        hv.hash = ngx_hash_key_lc(key.data, key.len);

    } else {
        hv.hash = 0;
    }

    hv.key = key;

    hv.offset = 0;
    hv.no_override = !override;
    hv.handler = NULL;

    //遍历预定义的 ngx_http_lua_set_handlers 数组，对在数组里的header进行调用其handler进行额外处理
    for (i = 0; handlers[i].name.len; i++) {
        //根据Key进行查找
        if (hv.key.len != handlers[i].name.len
            || ngx_strncasecmp(hv.key.data, handlers[i].name.data,
                               handlers[i].name.len) != 0)
        {
            dd("hv key comparison: %s <> %s", handlers[i].name.data,
               hv.key.data);

            continue;
        }

        dd("Matched handler: %s %s", handlers[i].name.data, hv.key.data);

        //赋值offset和handler
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;

        break;
    }

    //ngx_http_lua_set_handlers数组的最后一个元素，作为默认的处理方式，handler为 ngx_http_set_header
    if (handlers[i].name.len == 0 && handlers[i].handler) {
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;   //ngx_http_set_header
    }

#if 1
    if (hv.handler == NULL) {
        return NGX_ERROR;
    }
#endif

    if (r->headers_out.status == 400 || r->headers_in.headers.last == NULL) {
        /* must be a 400 Bad Request */
        return NGX_OK;
    }

    //调用ngx_http_lua_set_handlers数组元素定义的handler
    return hv.handler(r, &hv, &value);
}


/**
 * 从链表l中移除单个header
 * l: 要移除的header所在的单向链表l
 * cur: 要移除的heaner在l中所在的part
 * i: 要移除的heaner在所在part上的位置
 * 
 * 这个方法写得比较复杂，是因为要请求的header可能在单链表l的各个部分，需要考虑各种情况
 * 
 */
static ngx_int_t
ngx_http_lua_rm_header_helper(ngx_list_t *l, ngx_list_part_t *cur,
    ngx_uint_t i)
{
    ngx_table_elt_t             *data;
    ngx_list_part_t             *new, *part;

    dd("list rm item: part %p, i %d, nalloc %d", cur, (int) i,
       (int) l->nalloc);

    data = cur->elts;

    dd("cur: nelts %d, nalloc %d", (int) cur->nelts,
       (int) l->nalloc);

    dd("removing: \"%.*s:%.*s\"", (int) data[i].key.len, data[i].key.data,
       (int) data[i].value.len, data[i].value.data);

    //如果是cur中的第一个entry
    if (i == 0) {
        dd("first entry in the part");
        cur->elts = (char *) cur->elts + l->size;
        cur->nelts--;

        //如果cur是链表l的最后一个part
        if (cur == l->last) {
            dd("being the last part");
            //cur这个part只有一个元素，将cur从l中移除
            if (cur->nelts == 0) {
#if 1
                part = &l->part;
                dd("cur=%p, part=%p, part next=%p, last=%p",
                   cur, part, part->next, l->last);

                //如果cur就是l的首个part
                if (part == cur) {
                    //重置cur->elts指针(向前移动一个元素的长度)
                    cur->elts = (char *) cur->elts - l->size;
                    /* do nothing */

                } else {
                    //找到cur的前一个part
                    while (part->next != cur) {
                        if (part->next == NULL) {
                            return NGX_ERROR;
                        }

                        part = part->next;
                    }

                    //重置l->last
                    l->last = part;
                    //重置l->last->next
                    part->next = NULL;
                    dd("part nelts: %d", (int) part->nelts);
                    l->nalloc = part->nelts;
                }
#endif

            } else {
                //cur的元素个数大于1
                l->nalloc--;
                dd("nalloc decreased: %d", (int) l->nalloc);
            }

            return NGX_OK;
        }

        /* cur 不是l的最后一个part*/

        //说明cur中只有一个entry
        if (cur->nelts == 0) {
            dd("current part is empty");
            part = &l->part;
            if (part == cur) {
                ngx_http_lua_assert(cur->next != NULL);

                dd("remove 'cur' from the list by rewriting 'cur': "
                   "l->last: %p, cur: %p, cur->next: %p, part: %p",
                   l->last, cur, cur->next, part);

                if (l->last == cur->next) {
                    dd("last is cur->next");
                    l->part = *(cur->next);
                    l->last = part;
                    l->nalloc = part->nelts;

                } else {
                    l->part = *(cur->next);
                }

            } else {
                dd("remove 'cur' from the list");
                while (part->next != cur) {
                    if (part->next == NULL) {
                        return NGX_ERROR;
                    }

                    part = part->next;
                }

                part->next = cur->next;
            }

            return NGX_OK;
        }

        return NGX_OK;
    }

    if (i == cur->nelts - 1) {
        dd("last entry in the part");

        cur->nelts--;

        if (cur == l->last) {
            l->nalloc--;
        }

        return NGX_OK;
    }

    dd("the middle entry in the part");

    new = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (new == NULL) {
        return NGX_ERROR;
    }

    new->elts = &data[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    cur->nelts = i;
    cur->next = new;

    if (cur == l->last) {
        l->last = new;
        l->nalloc = new->nelts;
    }

    return NGX_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
