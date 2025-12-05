
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_util.h"


/**
 * 读取ngx.var.VAR_NAME值。两种格式：ngx.var.VAR_NAME 或 ngx.var[1]
 * 
 * name_data: VAR_NAME, 如果是ngx.var[1] 这种方法调用，name_data为NULL
 * name_len: VAR_NAME的长度。如果是ngx.var[1] 这种方法调用，name_len为0
 * lowcase_buf： 调用方申请的空间，如果是ngx.var[1] 这种方法调用，lowcase_buf为NULL
 * capture_id: VAR_NAME为字符串，此字段为0；为数字，此字段为数字值
 * value：出参，value指针
 * value_len: 出参，value长度指针
 * err：错误消息指针
 */
int
ngx_http_lua_ffi_var_get(ngx_http_request_t *r, u_char *name_data,
    size_t name_len, u_char *lowcase_buf, int capture_id, u_char **value,
    size_t *value_len, char **err)
{
    ngx_uint_t                   hash;
    ngx_str_t                    name;
    ngx_http_variable_value_t   *vv;

#if (NGX_PCRE)
    u_char                      *p;
    ngx_uint_t                   n;
    int                         *cap;
#endif

    if (r == NULL) {
        *err = "no request object found";
        return NGX_ERROR;
    }

    //fake request
    if ((r)->connection->fd == (ngx_socket_t) -1) {
        *err = "API disabled in the current context";
        return NGX_ERROR;
    }

#if (NGX_PCRE)
    //name_data==0, 说明是ngx.var[1] 这种调用方式。是正则表达式的匹配组
    if (name_data == 0) {
        if (capture_id <= 0) {
            return NGX_DECLINED;
        }

        /* it is a regex capturing variable */

        n = (ngx_uint_t) capture_id * 2;

        dd("n = %d, ncaptures = %d", (int) n, (int) r->ncaptures);

        if (r->captures == NULL
            || r->captures_data == NULL
            || n >= r->ncaptures)
        {
            return NGX_DECLINED;
        }

        /* n >= 0 && n < r->ncaptures */

        cap = r->captures;
        p = r->captures_data;

        *value = &p[cap[n]];
        *value_len = (size_t) (cap[n + 1] - cap[n]);

        return NGX_OK;
    }
#endif

#if (NGX_HTTP_V3)
    if (name_len == 9
        && r->http_version == NGX_HTTP_VERSION_30
        && ngx_strncasecmp(name_data, (u_char *) "http_host", 9) == 0
        && r->headers_in.server.data != NULL)
    {
        *value = r->headers_in.server.data;
        *value_len = r->headers_in.server.len;
        return NGX_OK;
    }
#endif

    //name_data转为小写
    hash = ngx_hash_strlow(lowcase_buf, name_data, name_len);

    name.data = lowcase_buf;
    name.len = name_len;

    dd("variable name: %.*s", (int) name_len, lowcase_buf);

    //通过小写的变量名获取变量值
    vv = ngx_http_get_variable(r, &name, hash);
    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    *value = vv->data;
    *value_len = vv->len;
    return NGX_OK;
}


/**
 * 设置ngx.var.VAR_NAME值
 * name_data: VAR_NAME值
 * name_len: VAR_NAME值长度
 * lowcase_buf: 用于存放小写的VAR_NAME
 * value: 要设置的value值
 * value_len: value长度
 * errbuf: 错误信息， 出参
 */
int
ngx_http_lua_ffi_var_set(ngx_http_request_t *r, u_char *name_data,
    size_t name_len, u_char *lowcase_buf, u_char *value, size_t value_len,
    u_char *errbuf, size_t *errlen)
{
    u_char                      *p;
    ngx_uint_t                   hash;
    ngx_http_variable_t         *v;
    ngx_http_variable_value_t   *vv;
    ngx_http_core_main_conf_t   *cmcf;

    if (r == NULL) {
        *errlen = ngx_snprintf(errbuf, *errlen, "no request object found")
                  - errbuf;
        return NGX_ERROR;
    }

    if ((r)->connection->fd == (ngx_socket_t) -1) {
        *errlen = ngx_snprintf(errbuf, *errlen,
                               "API disabled in the current context")
                  - errbuf;
        return NGX_ERROR;
    }

    //将name_data转为小写，同时计算hash
    hash = ngx_hash_strlow(lowcase_buf, name_data, name_len);

    dd("variable name: %.*s", (int) name_len, lowcase_buf);

    /* we fetch the variable itself */

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    //根据小写key hash 查找变量
    v = ngx_hash_find(&cmcf->variables_hash, hash, lowcase_buf, name_len);

    if (v) {
        //不允许重新设置值
        if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
            dd("variable not changeable");
            *errlen = ngx_snprintf(errbuf, *errlen,
                                   "variable \"%*s\" not changeable",
                                   name_len, lowcase_buf)
                      - errbuf;
            return NGX_ERROR;
        }

        //如果有set_handler
        if (v->set_handler) {

            dd("set variables with set_handler");

            if (value != NULL && value_len) {
                vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t)
                                + value_len);
                if (vv == NULL) {
                    goto nomem;
                }

                //p 为vv->data指针
                p = (u_char *) vv + sizeof(ngx_http_variable_value_t);
                //拷贝值
                ngx_memcpy(p, value, value_len);
                value = p;

            } else {
                //将变量置为null
                vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
                if (vv == NULL) {
                    goto nomem;
                }
            }

            //表示将变量置为NULL
            if (value == NULL) {
                vv->valid = 0;
                vv->not_found = 1;
                vv->no_cacheable = 0;
                vv->data = NULL;
                vv->len = 0;

            } else {
                //设置为新值
                vv->valid = 1;
                vv->not_found = 0;
                vv->no_cacheable = 0;

                vv->data = value;
                vv->len = value_len;
            }

            //调用set_handler
            v->set_handler(r, vv, v->data);
            return NGX_OK;
        }

        /* 变量没有set_handler */

        //如果变量被索引
        if (v->flags & NGX_HTTP_VAR_INDEXED) {
            //通过索引值获取变量值
            vv = &r->variables[v->index];

            dd("set indexed variable");

            //表示要清空变量值
            if (value == NULL) {
                vv->valid = 0;
                vv->not_found = 1;
                vv->no_cacheable = 0;

                vv->data = NULL;
                vv->len = 0;

            } else {
                //申请一个value_len长度的缓存
                p = ngx_palloc(r->pool, value_len);
                if (p == NULL) {
                    goto nomem;
                }

                //值拷贝
                ngx_memcpy(p, value, value_len);
                value = p;

                vv->valid = 1;
                vv->not_found = 0;
                vv->no_cacheable = 0;

                //重设值
                vv->data = value;
                vv->len = value_len;
            }

            return NGX_OK;
        }

        //报错
        *errlen = ngx_snprintf(errbuf, *errlen,
                               "variable \"%*s\" cannot be assigned "
                               "a value", name_len, lowcase_buf)
                  - errbuf;
        return NGX_ERROR;
    }

    /* variable not found */

    *errlen = ngx_snprintf(errbuf, *errlen,
                           "variable \"%*s\" not found for writing; "
                           "maybe it is a built-in variable that is not "
                           "changeable or you forgot to use \"set $%*s '';\" "
                           "in the config file to define it first",
                           name_len, lowcase_buf, name_len, lowcase_buf)
              - errbuf;
    return NGX_ERROR;

nomem:

    *errlen = ngx_snprintf(errbuf, *errlen, "no memory") - errbuf;
    return NGX_ERROR;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
