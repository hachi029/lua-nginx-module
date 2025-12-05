
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <nginx.h>
#include <ngx_md5.h>
#include "ngx_http_lua_common.h"
#include "ngx_http_lua_cache.h"
#include "ngx_http_lua_clfactory.h"
#include "ngx_http_lua_util.h"


static u_char *ngx_http_lua_gen_file_cache_key_helper(u_char *out,
    const u_char *src, size_t src_len);


/**
 * Find code chunk associated with the given key in code cache,
 * and push it to the top of Lua stack if found.
 *
 * Stack layout before call:
 *         |     ...    | <- top
 *
 * Stack layout after call:
 *         | code chunk | <- top
 *         |     ...    |
 *
 * */
/**
 * 
 * lua-nginx-module 它把所有的 Lua chunk 存放在 Lua 提供的注册表中（Registry），通过某个键，
 *  来获取到专门存放 chunk 的 code table，而这个键就是 ngx_http_lua_code_cache_key 这个 char 类型的变量的地址（一个全局变量，存放在全局/静态存储区），显然它是独一无二的
 * 
 * 然后再根据参数 key来作为 code table 的键，把对应的 Lua chunk 拿出来并存在栈顶。
 * 
 * 然后需要判断这个 chunk 是否是一个函数，是的话调用 lua_pcall 运行一次
 * 
 * 从lua_state的全局变量table LUA_REGISTRYINDEX 中加载代码，如果全局缓存中有就返回
 * 返回：
 *      NGX_ERROR：出错
 *      NGX_DECLINED：缓存未命中
 *      NGX_OK：缓存命中
 */
static ngx_int_t
ngx_http_lua_cache_load_code(ngx_log_t *log, lua_State *L,
    int *ref, const char *key)
{
#ifndef OPENRESTY_LUAJIT
    int          rc;
    u_char      *err;
#endif

    // 从 registry 全局注册表，找 ngx_http_lua_code_cache_key 的地址作为索引的值，并且把值 cache_table 入栈
    /*  get code cache table */
    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                          code_cache_key));
    //相当于  LUA_REGISTRYINDEX[‘ngx_http_lua_code_cache_key’][‘key’]以ngx_http_lua_code_cache_key为索引从全局注册表表中查找key对于的value
    lua_rawget(L, LUA_REGISTRYINDEX);    /*  sp++ */

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "code cache lookup (key='%s', ref=%d)", key, *ref);

    dd("code cache table to load: %p", lua_topointer(L, -1));

    if (!lua_istable(L, -1)) {
        dd("Error: code cache table to load did not exist!!");
        return NGX_ERROR;
    }

    ngx_http_lua_assert(key != NULL);

    if (*ref == LUA_NOREF) {
        lua_getfield(L, -1, key); /* cache closure */

    } else {
        if (*ref == LUA_REFNIL) {
            lua_getfield(L, -1, key); /* cache ref */

            if (!lua_isnumber(L, -1)) {
                goto not_found;
            }

            *ref = lua_tonumber(L, -1);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "code cache setting ref (key='%s', ref=%d)",
                           key, *ref);

            lua_pop(L, 1); /* cache */
        }

        lua_rawgeti(L, -1, *ref); /* cache closure */
    }

    // 如果value存在并且为一个函数，因为这里的函数体是 return function() … end包裹的  所以在56行需要再调用lua_pcall执行以下，以获得返回的函数并将返回的函数结果放到栈顶,并将 LUA_REGISTRYINDEX从栈中移除
    if (lua_isfunction(L, -1)) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "code cache hit (key='%s', ref=%d)", key, *ref);

#ifdef OPENRESTY_LUAJIT
        lua_remove(L, -2);   /*  sp-- */
        return NGX_OK;
#else
        /*  call closure factory to gen new closure */
        rc = lua_pcall(L, 0, 1, 0);
        if (rc == 0) {
            /*  remove cache table from stack, leave code chunk at
             *  top of stack */
            lua_remove(L, -2);   /*  sp-- */
            return NGX_OK;
        }

        if (lua_isstring(L, -1)) {
            err = (u_char *) lua_tostring(L, -1);

        } else {
            err = (u_char *) "unknown error";
        }

        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "lua: failed to run factory at key \"%s\": %s",
                      key, err);
        lua_pop(L, 2);
        return NGX_ERROR;
#endif /* OPENRESTY_LUAJIT */
    }

not_found:

    dd("Value associated with given key in code cache table is not code "
       "chunk: stack top=%d, top value type=%s\n",
       lua_gettop(L), luaL_typename(L, -1));

    /*  remove cache table and value from stack */
    lua_pop(L, 2);                                /*  sp-=2 */

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "code cache miss (key='%s', ref=%d)", key, *ref);

    return NGX_DECLINED;
}


/**
 * Store the closure factory at the top of Lua stack to code cache, and
 * associate it with the given key. Then generate new closure.
 *
 * Stack layout before call:
 *         | code factory | <- top
 *         |     ...      |
 *
 * Stack layout after call:
 *         | code chunk | <- top
 *         |     ...    |
 *
 * */
/**
 * 把代码按Key存放到lua_state的全局变量table中
 */
static ngx_int_t
ngx_http_lua_cache_store_code(lua_State *L, int *ref, const char *key)
{
#ifndef OPENRESTY_LUAJIT
    int rc;
#endif

     // 从 registry 全局注册表，找 ngx_http_lua_code_cache_key 的地址作为索引的值，并且把值入栈，是一个 cache_code_table
    /*  get code cache table */
    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                          code_cache_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    dd("Code cache table to store: %p", lua_topointer(L, -1));

    if (!lua_istable(L, -1)) {
        dd("Error: code cache table to load did not exist!!");
        return NGX_ERROR;
    }

    ngx_http_lua_assert(key != NULL);

    // 把原本栈顶现在 [-2] 的代码块复制再入栈
    lua_pushvalue(L, -2); /* closure cache closure */

    if (*ref == LUA_NOREF) {
        // 把栈顶的代码块以 key 作为索引值，插入到 cache_code_table，并出栈复制出来的代码块
        /*  cache closure by cache key */
        lua_setfield(L, -2, key); /* closure cache */

    } else {
        /*  cache closure with reference */
        *ref = luaL_ref(L, -2); /* closure cache */

        /*  cache reference by cache key */
        lua_pushnumber(L, *ref); /* closure cache ref */
        lua_setfield(L, -2, key); /* closure cache */
    }

     // 把 cache_code_table 出栈
    /*  remove cache table, leave closure factory at top of stack */
    lua_pop(L, 1); /* closure */

#ifndef OPENRESTY_LUAJIT
    /*  call closure factory to generate new closure */
    rc = lua_pcall(L, 0, 1, 0);
    if (rc != 0) {
        dd("Error: failed to call closure factory!!");
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


/**
 * 获取解析后的lua代码
 * *src: inline script or scriptfile path
 * src_len: 
 * *cache_ref
 * *cache_key:
 * *name: chunkname
 * 
 * 
 * 1.调用 ngx_http_lua_cache_load_code，判断当前的 Lua chunk 有没有缓存，得到返回码，如果返回码为 NGX_OK，跳到第二步；如果返回码是 NGX_ERROR，跳到第三步；否则跳到第四步
 * 2.从缓存中拿到 Lua chunk 且被压入到栈，返回 NGX_OK
 * 3.出错，返回 NGX_ERROR
 * 4.缓存 Miss，从原生的 Lua 代码加载，然后压栈，如果出错，记录错误日志然后返回 NGX_ERROR；否则返回 NGX_OK
 * 
 */
ngx_int_t
ngx_http_lua_cache_loadbuffer(ngx_log_t *log, lua_State *L,
    const u_char *src, size_t src_len, int *cache_ref, const u_char *cache_key,
    const char *name)
{
    int          n;
    ngx_int_t    rc;
    const char  *err = NULL;

    n = lua_gettop(L);

    //判断当前的 Lua chunk 有没有缓存，得到返回码
    rc = ngx_http_lua_cache_load_code(log, L, cache_ref, (char *) cache_key);
    //如果返回码为 NGX_OK, 标识缓存命中，代码块缓存已经被压入栈了
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    //出错，返回 NGX_ERROR。
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    //rc == NGX_DECLINED, 缓存 Miss，从原生的 Lua 代码加载，然后压栈，如果出错，记录错误日志然后返回。NGX_ERROR；否则返回 NGX_OK
    /* rc == NGX_DECLINED */

    /* load closure factory of inline script to the top of lua stack, sp++ */
    // 从字符串 src 生成 Lua 代码块
    rc = ngx_http_lua_clfactory_loadbuffer(L, (char *) src, src_len, name);

    if (rc != 0) {
        /*  Oops! error occurred when loading Lua script */
        if (rc == LUA_ERRMEM) {
            err = "memory allocation error";

        } else {
            if (lua_isstring(L, -1)) {
                err = lua_tostring(L, -1);

            } else {
                err = "unknown error";
            }
        }

        goto error;
    }

    /*  store closure factory and gen new closure at the top of lua stack to
     *  code cache */
    // 把刚加载的 Lua 代码块按 cache_key 索引存储起来 
    rc = ngx_http_lua_cache_store_code(L, cache_ref, (char *) cache_key);
    if (rc != NGX_OK) {
        err = "fail to generate new closure from the closure factory";
        goto error;
    }

    return NGX_OK;

error:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "failed to load inlined Lua code: %s", err);
    lua_settop(L, n);
    return NGX_ERROR;
}


/**
 * 完成lua代码加载动作
 * 
 * *script: lua脚本文件路径，'\0' 结尾
 * *cache_ref：
 * *cache_key: 
 */
ngx_int_t
ngx_http_lua_cache_loadfile(ngx_log_t *log, lua_State *L,
    const u_char *script, int *cache_ref, const u_char *cache_key)
{
    int              n;
    ngx_int_t        rc, errcode = NGX_ERROR;
    u_char           buf[NGX_HTTP_LUA_FILE_KEY_LEN + 1];
    const char      *err = NULL;

    n = lua_gettop(L);

    /*  calculate digest of script file path */
    if (cache_key == NULL) {
        dd("CACHE file key not pre-calculated...calculating");

        //生成cache_key
        cache_key = ngx_http_lua_gen_file_cache_key_helper(buf, script,
                                                           ngx_strlen(script));
        *cache_ref = LUA_NOREF;

    } else {
        dd("CACHE file key already pre-calculated");

        ngx_http_lua_assert(cache_ref != NULL && *cache_ref != LUA_NOREF);
    }

    //1.从lua_state的全局变量table中加载代码，如果全局缓存中有就返回
    rc = ngx_http_lua_cache_load_code(log, L, cache_ref, (char *) cache_key);
    //全局变量中存在，则返回
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* rc == NGX_DECLINED */

    /*  load closure factory of script file to the top of lua stack, sp++ */
    //2.用自定义的函数从文件中加载代码
    //如果代码缓存关闭的时候，openresty会为每一个请求创建新的lua_state，这样请求来临的时候在全局变量中找不到对应的代码缓存，都需要到下一步ngx_http_lua_clfactory_loadfile中读取文件加载
    //如果代码缓存打开的时候，openresty会使用ngx_http_lua_module全局的lua_state，这样只有新的lua文件 在首次加载时需要到下一步ngx_http_lua_clfactory_loadfile中 读取文件加载，第二次来的时候 便可以在lua_state对应的全局变量中找到了
    rc = ngx_http_lua_clfactory_loadfile(L, (char *) script);

    dd("loadfile returns %d (%d)", (int) rc, LUA_ERRFILE);

    if (rc != 0) {
        /*  Oops! error occurred when loading Lua script */
        switch (rc) {
        case LUA_ERRMEM:
            err = "memory allocation error";
            break;

        case LUA_ERRFILE:
            if (errno == ENOENT) {
                errcode = NGX_HTTP_NOT_FOUND;

            } else {
                errcode = NGX_HTTP_SERVICE_UNAVAILABLE;
            }

            /* fall through */

        default:
            if (lua_isstring(L, -1)) {
                err = lua_tostring(L, -1);

            } else {
                err = "unknown error";
            }
        }

        goto error;
    }

    /*  store closure factory and gen new closure at the top of lua stack
     *  to code cache */
    //3.把代码存放到lua_state的全局变量table中
    rc = ngx_http_lua_cache_store_code(L, cache_ref, (char *) cache_key);
    if (rc != NGX_OK) {
        err = "fail to generate new closure from the closure factory";
        goto error;
    }

    return NGX_OK;

error:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "failed to load external Lua file \"%s\": %s", script, err);

    lua_settop(L, n);
    return errcode;
}


/**
 * 生成代码块缓存用的 key，示例：rewrite_by_lua_nhli_6f30fa99b87d7f63b59c913687f45f65
 * tag+tag_len+_digest_hex(src)
 */
u_char *
ngx_http_lua_gen_chunk_cache_key(ngx_conf_t *cf, const char *tag,
    const u_char *src, size_t src_len)
{
    u_char      *p, *out;
    size_t       tag_len;

    tag_len = ngx_strlen(tag);

    out = ngx_palloc(cf->pool, tag_len + NGX_HTTP_LUA_INLINE_KEY_LEN + 2);
    if (out == NULL) {
        return NULL;
    }

    p = ngx_copy(out, tag, tag_len);
    p = ngx_copy(p, "_", 1);
    p = ngx_copy(p, NGX_HTTP_LUA_INLINE_TAG, NGX_HTTP_LUA_INLINE_TAG_LEN);
    //计算Lua代码块的md5_hex
    p = ngx_http_lua_digest_hex(p, src, src_len);
    *p = '\0';

    return out;
}


/**
 * 生成Lua code 的cache_key 
 */
static u_char *
ngx_http_lua_gen_file_cache_key_helper(u_char *out, const u_char *src,
    size_t src_len)
{
    u_char      *p;

    ngx_http_lua_assert(out != NULL);

    if (out == NULL) {
        return NULL;
    }

    p = ngx_copy(out, NGX_HTTP_LUA_FILE_TAG, NGX_HTTP_LUA_FILE_TAG_LEN);
    p = ngx_http_lua_digest_hex(p, src, src_len);
    *p = '\0';

    return out;
}


u_char *
ngx_http_lua_gen_file_cache_key(ngx_conf_t *cf, const u_char *src,
    size_t src_len)
{
    u_char      *out;

    out = ngx_palloc(cf->pool, NGX_HTTP_LUA_FILE_KEY_LEN + 1);
    if (out == NULL) {
        return NULL;
    }

    return ngx_http_lua_gen_file_cache_key_helper(out, src, src_len);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
