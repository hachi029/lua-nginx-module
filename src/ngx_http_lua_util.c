
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "nginx.h"
#include "ngx_http_lua_directive.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_pcrefix.h"
#include "ngx_http_lua_args.h"
#include "ngx_http_lua_uri.h"
#include "ngx_http_lua_req_body.h"
#include "ngx_http_lua_headers.h"
#include "ngx_http_lua_output.h"
#include "ngx_http_lua_control.h"
#include "ngx_http_lua_ndk.h"
#include "ngx_http_lua_subrequest.h"
#include "ngx_http_lua_log.h"
#include "ngx_http_lua_string.h"
#include "ngx_http_lua_misc.h"
#include "ngx_http_lua_consts.h"
#include "ngx_http_lua_shdict.h"
#include "ngx_http_lua_coroutine.h"
#include "ngx_http_lua_socket_tcp.h"
#include "ngx_http_lua_socket_udp.h"
#include "ngx_http_lua_sleep.h"
#include "ngx_http_lua_setby.h"
#include "ngx_http_lua_headerfilterby.h"
#include "ngx_http_lua_bodyfilterby.h"
#include "ngx_http_lua_logby.h"
#include "ngx_http_lua_probe.h"
#include "ngx_http_lua_uthread.h"
#include "ngx_http_lua_contentby.h"
#include "ngx_http_lua_timer.h"
#include "ngx_http_lua_config.h"
#include "ngx_http_lua_socket_tcp.h"
#include "ngx_http_lua_ssl_certby.h"
#include "ngx_http_lua_ssl.h"
#include "ngx_http_lua_log_ringbuf.h"
#if (NGX_THREADS)
#include "ngx_http_lua_worker_thread.h"
#endif
#if (NGX_HTTP_V3)
#include <ngx_event_quic.h>
#include <ngx_event_quic_connection.h>
#endif


#if 1
#undef ngx_http_lua_probe_info
#define ngx_http_lua_probe_info(msg)
#endif


#ifndef NGX_HTTP_LUA_BT_DEPTH
#define NGX_HTTP_LUA_BT_DEPTH  22
#endif


#ifndef NGX_HTTP_LUA_BT_MAX_COROS
#define NGX_HTTP_LUA_BT_MAX_COROS  5
#endif


#if (NGX_HTTP_LUA_HAVE_SA_RESTART)
#define NGX_HTTP_LUA_SA_RESTART_SIGS {                                       \
    ngx_signal_value(NGX_RECONFIGURE_SIGNAL),                                \
    ngx_signal_value(NGX_REOPEN_SIGNAL),                                     \
    ngx_signal_value(NGX_NOACCEPT_SIGNAL),                                   \
    ngx_signal_value(NGX_TERMINATE_SIGNAL),                                  \
    ngx_signal_value(NGX_SHUTDOWN_SIGNAL),                                   \
    ngx_signal_value(NGX_CHANGEBIN_SIGNAL),                                  \
    SIGALRM,                                                                 \
    SIGINT,                                                                  \
    SIGIO,                                                                   \
    SIGCHLD,                                                                 \
    SIGSYS,                                                                  \
    SIGPIPE,                                                                 \
    0                                                                        \
};
#endif


//	 register table to cache user code
char ngx_http_lua_code_cache_key;
// Lua socket connection pool table 连接池
char ngx_http_lua_socket_pool_key;
// 保存所有协程的table
char ngx_http_lua_coroutines_key;
char ngx_http_lua_headers_metatable_key;


//字面量"location"的hash值
ngx_uint_t  ngx_http_lua_location_hash = 0;
//字面量"content-length"的hash值
ngx_uint_t  ngx_http_lua_content_length_hash = 0;


static ngx_int_t ngx_http_lua_send_http10_headers(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static void ngx_http_lua_init_registry(lua_State *L, ngx_log_t *log);
static void ngx_http_lua_init_globals(lua_State *L, ngx_cycle_t *cycle,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log);
#ifdef OPENRESTY_LUAJIT
static void ngx_http_lua_inject_global_write_guard(lua_State *L,
    ngx_log_t *log);
#endif
static void ngx_http_lua_set_path(ngx_cycle_t *cycle, lua_State *L, int tab_idx,
    const char *fieldname, const char *path, const char *default_path,
    ngx_log_t *log);
static ngx_int_t ngx_http_lua_handle_exec(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static ngx_int_t ngx_http_lua_handle_exit(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static ngx_int_t ngx_http_lua_handle_rewrite_jump(lua_State *L,
    ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx);
static int ngx_http_lua_thread_traceback(lua_State *L, lua_State *co,
    ngx_http_lua_co_ctx_t *coctx);
static void ngx_http_lua_inject_ngx_api(lua_State *L,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log);
static void ngx_http_lua_inject_arg_api(lua_State *L);
static int ngx_http_lua_param_set(lua_State *L);
static ngx_int_t ngx_http_lua_output_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_lua_send_special(ngx_http_request_t *r,
    ngx_uint_t flags);
static void ngx_http_lua_finalize_threads(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, lua_State *L);
static ngx_int_t ngx_http_lua_post_zombie_thread(ngx_http_request_t *r,
    ngx_http_lua_co_ctx_t *parent, ngx_http_lua_co_ctx_t *thread);
static void ngx_http_lua_cleanup_zombie_child_uthreads(ngx_http_request_t *r,
    lua_State *L, ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t *coctx);
static ngx_int_t ngx_http_lua_on_abort_resume(ngx_http_request_t *r);
static void ngx_http_lua_close_fake_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_flush_pending_output(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static ngx_int_t
    ngx_http_lua_process_flushing_coroutines(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static lua_State *ngx_http_lua_new_state(lua_State *parent_vm,
    ngx_cycle_t *cycle, ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log);
static int ngx_http_lua_get_raw_phase_context(lua_State *L);


#ifndef LUA_PATH_SEP
#define LUA_PATH_SEP ";"
#endif


#if !defined(LUA_DEFAULT_PATH) && (NGX_DEBUG)
#define LUA_DEFAULT_PATH "../lua-resty-core/lib/?.lua;"                      \
                         "../lua-resty-lrucache/lib/?.lua"
#endif


#define AUX_MARK "\1"


/**
 * 设置lua虚拟机查找lua时的path
 */
static void
ngx_http_lua_set_path(ngx_cycle_t *cycle, lua_State *L, int tab_idx,
    const char *fieldname, const char *path, const char *default_path,
    ngx_log_t *log)
{
    const char          *tmp_path;
    const char          *prefix;

    /* XXX here we use some hack to simplify string manipulation */
    tmp_path = luaL_gsub(L, path, LUA_PATH_SEP LUA_PATH_SEP,
                         LUA_PATH_SEP AUX_MARK LUA_PATH_SEP);

    lua_pushlstring(L, (char *) cycle->prefix.data, cycle->prefix.len);
    prefix = lua_tostring(L, -1);
    tmp_path = luaL_gsub(L, tmp_path, "$prefix", prefix);
    tmp_path = luaL_gsub(L, tmp_path, "${prefix}", prefix);
    lua_pop(L, 3);

    dd("tmp_path path: %s", tmp_path);

#if (NGX_DEBUG)
    tmp_path =
#else
    (void)
#endif
        luaL_gsub(L, tmp_path, AUX_MARK, default_path);

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua setting lua package.%s to \"%s\"", fieldname, tmp_path);
#endif

    lua_remove(L, -2);

    /* fix negative index as there's new data on stack */
    tab_idx = (tab_idx < 0) ? (tab_idx - 1) : tab_idx;
    lua_setfield(L, tab_idx, fieldname);
}


#ifndef OPENRESTY_LUAJIT
/**
 * Create new table and set _G field to itself.
 *
 * After:
 *         | new table | <- top
 *         |    ...    |
 * */
/**
 * t[_G]=t
 */
void
ngx_http_lua_create_new_globals_table(lua_State *L, int narr, int nrec)
{
    lua_createtable(L, narr, nrec + 1);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
}
#endif /* OPENRESTY_LUAJIT */


/**
 * ngx_http_lua_init->ngx_http_lua_init_vm->.
 * 创建一个lua虚拟机实例 L， 并且设置lua_path、lua_cpath，同时注册ngx.* api
 */
static lua_State *
ngx_http_lua_new_state(lua_State *parent_vm, ngx_cycle_t *cycle,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log)
{
    lua_State       *L;
    const char      *old_path;
    const char      *new_path;
    size_t           old_path_len;
    const char      *old_cpath;
    const char      *new_cpath;
    size_t           old_cpath_len;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "lua creating new vm state");

    /**
     * 
     * luaL_newstate 是 Lua C API 中的一个函数，用于创建一个新的 Lua 状态机。
     * 状态机是 Lua C API 中非常重要的概念，它代表了 Lua 环境的上下文，其中包含了 Lua 堆栈、全局环境、注册表以及所有 Lua 相关的状态信息
     * 这个函数返回一个指向新创建的 lua_State 结构的指针，这个结构包含了 Lua 状态机的所有信息
     * 
     * 当完成对 Lua 状态机的所有操作后，应该使用 lua_close 函数来释放与其相关的所有资源。
     */
    L = luaL_newstate();
    if (L == NULL) {
        return NULL;
    }

    // Lua API ：打开指定状态机中的所有 Lua 标准库。
    luaL_openlibs(L);

    // 把全局的 package table 入栈，是一个模块导出函数列表
    lua_getglobal(L, "package");

    if (!lua_istable(L, -1)) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "the \"package\" table does not exist");
        return NULL;
    }

    // 初始化 package table 的 path 和 cpath ， 也就是搜索路径
    if (parent_vm) {
        // 如果有 parent_vm ，将其path/cpath 继承过来。
        lua_getglobal(parent_vm, "package");
        //newVM.package.path = parentVM.package.path
        lua_getfield(parent_vm, -1, "path");
        old_path = lua_tolstring(parent_vm, -1, &old_path_len);
        lua_pop(parent_vm, 1);

        lua_pushlstring(L, old_path, old_path_len);
        lua_setfield(L, -2, "path");

        //newVM.package.cpath = parentVM.package.cpath
        lua_getfield(parent_vm, -1, "cpath");
        old_path = lua_tolstring(parent_vm, -1, &old_path_len);
        lua_pop(parent_vm, 2);

        lua_pushlstring(L, old_path, old_path_len);
        lua_setfield(L, -2, "cpath");

    } else {
#ifdef LUA_DEFAULT_PATH
#   define LUA_DEFAULT_PATH_LEN (sizeof(LUA_DEFAULT_PATH) - 1)
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua prepending default package.path with %s",
                       LUA_DEFAULT_PATH);
        // 这个是用 lua_package_path 以及 lua_package_cpath 指令设置的路径初始化 package 的搜索路径
        lua_pushliteral(L, LUA_DEFAULT_PATH ";"); /* package default */
        //package.path=';'
        lua_getfield(L, -2, "path"); /* package default old */
        lua_concat(L, 2); /* package new */
        lua_setfield(L, -2, "path"); /* package */
#endif

#ifdef LUA_DEFAULT_CPATH
#   define LUA_DEFAULT_CPATH_LEN (sizeof(LUA_DEFAULT_CPATH) - 1)
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua prepending default package.cpath with %s",
                       LUA_DEFAULT_CPATH);

        lua_pushliteral(L, LUA_DEFAULT_CPATH ";"); /* package default */
        lua_getfield(L, -2, "cpath"); /* package default old */
        lua_concat(L, 2); /* package new */
        lua_setfield(L, -2, "cpath"); /* package */
#endif

        //设置lua_path
        if (lmcf->lua_path.len != 0) {
            lua_getfield(L, -1, "path"); /* get original package.path */
            old_path = lua_tolstring(L, -1, &old_path_len);

            dd("old path: %s", old_path);

            lua_pushlstring(L, (char *) lmcf->lua_path.data,
                            lmcf->lua_path.len);
            new_path = lua_tostring(L, -1);

            ngx_http_lua_set_path(cycle, L, -3, "path", new_path, old_path,
                                  log);

            lua_pop(L, 2);
        }

        //设置lua_cpath
        if (lmcf->lua_cpath.len != 0) {
            lua_getfield(L, -1, "cpath"); /* get original package.cpath */
            old_cpath = lua_tolstring(L, -1, &old_cpath_len);

            dd("old cpath: %s", old_cpath);

            lua_pushlstring(L, (char *) lmcf->lua_cpath.data,
                            lmcf->lua_cpath.len);
            new_cpath = lua_tostring(L, -1);

            ngx_http_lua_set_path(cycle, L, -3, "cpath", new_cpath, old_cpath,
                                  log);


            // package table 操作完毕，出栈
            lua_pop(L, 2);
        }
    }

    lua_pop(L, 1); /* remove the "package" table */

    //初始化lua registry table
    ngx_http_lua_init_registry(L, log);
    //初始化global全局变量，创建了ngx表，并注入Lua Ngx API
    ngx_http_lua_init_globals(L, cycle, lmcf, log);

    return L;
}


/**
 * 创建一个新的协程(coroutine)
 * 
 * 所有的协程保存在一个table中，这个table保存在registry里面
 * 
 * 当协程结束或者被丢弃时，通过 luaL_unref 把协程对象从这个 registry 里的 table 中去除引用，从而让 Lua GC 回收之。
 * 
 *  *L: 为全局的协程
 *  *ref: 出参
 */
lua_State *
ngx_http_lua_new_thread(ngx_http_request_t *r, lua_State *L, int *ref)
{
    int              base;
    lua_State       *co;

#ifdef HAVE_LUA_RESETTHREAD
    ngx_queue_t     *q;

    ngx_http_lua_main_conf_t    *lmcf;
    ngx_http_lua_thread_ref_t   *tref;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua creating new thread");

    //获取模块配置
    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

    //检查是否有缓存的协程，有就直接复用
    if (L == lmcf->lua && !ngx_queue_empty(&lmcf->cached_lua_threads)) {
        //取出队首元素，拿到其co和ref属性
        q = ngx_queue_head(&lmcf->cached_lua_threads);
        tref = ngx_queue_data(q, ngx_http_lua_thread_ref_t, queue);

        ngx_http_lua_assert(tref->ref != LUA_NOREF);
        ngx_http_lua_assert(tref->co != NULL);

        //获取缓存元素的co和ref
        co = tref->co;
        *ref = tref->ref;

        //将tref置空后，放回lmcf->free_lua_threads
        tref->co = NULL;
        tref->ref = LUA_NOREF;

        //将q从lmcf->cached_lua_threads上移除
        ngx_queue_remove(q);
        //将q加入到 lmcf->free_lua_threads
        ngx_queue_insert_head(&lmcf->free_lua_threads, q);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua reusing cached lua thread %p (ref %d)", co, *ref);

#if 0
        {
            int n = 0;
            lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                                  coroutines_key));
            lua_rawget(L, LUA_REGISTRYINDEX);
            lua_pushnil(L);  /* first key */
            while (lua_next(L, -2) != 0) {
                if (!lua_isnil(L, -1) && !lua_isnil(L, -2)) {
                    n++;
                }

                lua_pop(L, 1);
            }

            lua_pop(L, 1);

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "! lua reusing cached lua thread %p (ref %d, n %d)",
                           co, *ref, n);
        }
#endif

    } else
#endif
    {

        /**
         * 设置协程的全局表
             新建表 t，并设置 t["_G"] = t，从而在 Lua 代码中可以通过 ["_G"] 访问到全局表
             新建表 mt，设置 mt["__index"] = global_table（当前的全局表）
             设置 mt 作为 t 的元表
             设置 t 为协程新的全局表
             这时候，即可同时访问 t 和 原 global_table 的内容
                子协程可以访问父协程的内容，而子协程之间无法互相访问
            为协程创建引用，以能快速在 coroutines_key 注册表中找到协程

        总体流程用新建的全局表替换了旧的全局表，其中新的全局表的_G字段是它自己，新全局表的元表中__index元方法是旧的全局表
         */

        // 记一个 top 的索引
        base = lua_gettop(L);

        // 使用 ngx_http_lua_coroutines_key 的地址作为索引，在 register 全局注册表中找到 corutine_table 入栈
        lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                              coroutines_key));
        //相当于将registry_table[ngx_http_lua_coroutines_key]这个table放到栈顶
        lua_rawget(L, LUA_REGISTRYINDEX);

        // 用 Lua 虚拟机 L 创建一条新协程，并将其压栈，并返回维护这个线程的 lua_State 赋值给 co
        //这时栈顶为lua_State *co，registry_table[ngx_http_lua_coroutines_key]变为-2
        co = lua_newthread(L);

#ifndef OPENRESTY_LUAJIT
        /*  {{{ inherit coroutine's globals to main thread's globals table
         *  for print() function will try to find tostring() in current
         *  globals table.
         */
        /*  new globals table for coroutine */
        //t[_G]=t
        ngx_http_lua_create_new_globals_table(co, 0, 0);

        //创建一张mt表
        lua_createtable(co, 0, 1);
        /* 拿到全局表 */
        ngx_http_lua_get_globals_table(co);
        //设置mt的__index为全局表：
        lua_setfield(co, -2, "__index");
        //设置mt为新协程全局表的元表
        lua_setmetatable(co, -2);

        //这么做，所有的子协程只能共享父协程的全局变量而不能相互共享其他子协程的全局变量

        /* 设置协程新的全局表到对应索引，其_G field是自己，
        其元表是新表，新表的__index是父协程的全局表 */
        ngx_http_lua_set_globals_table(co);
        /*  }}} */
#endif /* OPENRESTY_LUAJIT */

         //Lua虚拟机中为这个新协程创建一个reference：
        *ref = luaL_ref(L, -2);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                       ngx_cycle->log, 0, "lua ref lua thread %p (ref %d)", co,
                       *ref);

        if (*ref == LUA_NOREF) {
            lua_settop(L, base);  /* restore main thread stack */
            return NULL;
        }

        //恢复主协程的堆栈
        // 完成所有操作了，删除 base 之上的数据，恢复栈状态
        //这里pop之后，gc会回收栈顶的cr，所以需要将cr引用保存起来。也就是上面的luaL_ref()所做的事情。
        lua_settop(L, base);
    }

    return co;
}


/**
 * 将协程对象放入 lmcf->cached_lua_threads 缓存队列中(如果对协程对象进行缓存)
 * 从注册表中保存所有协程的table中删除协程 (如果不对协程对象进行缓存)
 */
void
ngx_http_lua_del_thread(ngx_http_request_t *r, lua_State *L,
    ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t *coctx)
{
#ifdef HAVE_LUA_RESETTHREAD
    ngx_queue_t                 *q;
    ngx_http_lua_main_conf_t    *lmcf;
    ngx_http_lua_thread_ref_t   *tref;
#endif

    if (coctx->co_ref == LUA_NOREF) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua deleting light thread %p (ref %d)", coctx->co,
                   coctx->co_ref);

    ngx_http_lua_probe_thread_delete(r, coctx->co, ctx);

#ifdef HAVE_LUA_RESETTHREAD
    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

    if (ctx != NULL
        && coctx->co == ctx->entry_co_ctx.co
        && L == lmcf->lua && !ngx_queue_empty(&lmcf->free_lua_threads))
    {
        lua_resetthread(L, coctx->co);
        //从lmcf->free_lua_threads 取出一个 ngx_http_lua_thread_ref_t 结构体
        q = ngx_queue_head(&lmcf->free_lua_threads);
        tref = ngx_queue_data(q, ngx_http_lua_thread_ref_t, queue);

        ngx_http_lua_assert(tref->ref == LUA_NOREF);
        ngx_http_lua_assert(tref->co == NULL);

        //设置co和co_ref
        tref->ref = coctx->co_ref;
        tref->co = coctx->co;

        //将 ngx_http_lua_thread_ref_t 结构体从 lmcf->free_lua_threads移除
        ngx_queue_remove(q);
        //将 ngx_http_lua_thread_ref_t 放入 lmcf->cached_lua_threads 队列
        ngx_queue_insert_head(&lmcf->cached_lua_threads, q);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua caching unused lua thread %p (ref %d)", coctx->co,
                       coctx->co_ref);

    } else {
#endif
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http lua unref thread %p: %d", coctx->co,
                       coctx->co_ref);

        lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                              coroutines_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        //unref 让gc 进行回收
        luaL_unref(L, -1, coctx->co_ref);
        lua_pop(L, 1);
#ifdef HAVE_LUA_RESETTHREAD
    }
#endif

    coctx->co_ref = LUA_NOREF;
    coctx->co_status = NGX_HTTP_LUA_CO_DEAD;
}


/**
 * 获取文件全路径。如果不是绝对路径，添加&ngx_cycle->prefix 前缀
 */
u_char *
ngx_http_lua_rebase_path(ngx_pool_t *pool, u_char *src, size_t len)
{
    u_char     *p;
    ngx_str_t   dst;

    //1.申请新的内存，末尾添加'\0'
    dst.data = ngx_palloc(pool, len + 1);
    if (dst.data == NULL) {
        return NULL;
    }

    dst.len = len;

    p = ngx_copy(dst.data, src, len);
    *p = '\0';

    //2.路径转为绝对路径
    if (ngx_get_full_name(pool, (ngx_str_t *) &ngx_cycle->prefix, &dst)
        != NGX_OK)
    {
        return NULL;
    }

    return dst.data;
}


/**
 * 根据条件判断是否调用 ngx_http_send_header
 */
ngx_int_t
ngx_http_lua_send_header_if_needed(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t            rc;

    dd("send header if needed: %d", r->header_sent || ctx->header_sent);

    //如果还没有发送header，否则直接返回NGX_OK
    if (!r->header_sent && !ctx->header_sent) {
        //默认status为OK
        if (r->headers_out.status == 0) {
            r->headers_out.status = NGX_HTTP_OK;
        }

        if (!ctx->mime_set
            && ngx_http_lua_set_content_type(r, ctx) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (!ctx->headers_set) {
            ngx_http_clear_content_length(r);
            ngx_http_clear_accept_ranges(r);
        }

        if (!ctx->buffering) {
            dd("sending headers");
            rc = ngx_http_send_header(r);
            if (r->filter_finalize) {
                ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
            }

            ctx->header_sent = 1;
            return rc;
        }
    }

    return NGX_OK;
}


/**
 * 将in表示的缓冲区发送到客户端
 * 
 * in如果是NULL， 则表示发送一个last_buf标志的buf
 * 
 */
ngx_int_t
ngx_http_lua_send_chain_link(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t                     rc;
    ngx_chain_t                  *cl;
    ngx_chain_t                 **ll;
    ngx_http_lua_loc_conf_t      *llcf;

#if 1
    //如果获取了raw socket了或已经发送了eof了
    if (ctx->acquired_raw_req_socket || ctx->eof) {
        dd("ctx->eof already set or raw req socket already acquired");
        return NGX_OK;
    }
#endif

    //如果是HEAD请求
    if ((r->method & NGX_HTTP_HEAD) && !r->header_only) {
        r->header_only = 1;
    }

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (llcf->http10_buffering
        && !ctx->buffering
        && !r->header_sent
        && !ctx->header_sent
        && r->http_version < NGX_HTTP_VERSION_11
        && r->headers_out.content_length_n < 0)
    {
        ctx->buffering = 1;
    }

    //发送响应头
    rc = ngx_http_lua_send_header_if_needed(r, ctx);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    //不需要发送响应体
    if (r->header_only) {
        ctx->eof = 1;

        //还没有读取请求体
        if (!r->request_body && r == r->main) {
            //读取并丢弃
            if (ngx_http_discard_request_body(r) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ctx->buffering) {
            return ngx_http_lua_send_http10_headers(r, ctx);
        }

        return rc;
    }

    //参考ngx.eof()/ngx_http_lua_ngx_eof
    if (in == NULL) {
        dd("last buf to be sent");

#if 1
         //还没有读取请求体
        if (!r->request_body && r == r->main) {
            //读取并丢弃
            if (ngx_http_discard_request_body(r) != NGX_OK) {
                return NGX_ERROR;
            }
        }
#endif

        if (ctx->buffering) {
            rc = ngx_http_lua_send_http10_headers(r, ctx);
            if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            if (ctx->out) {

                rc = ngx_http_lua_output_filter(r, ctx->out);

                if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                    return rc;
                }

                ctx->out = NULL;
            }
        }

        //标识已经发送了last_buf了。last_buf=1
        ctx->eof = 1;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua sending last buf of the response body");

        //发送一个有last_buf标志的ngx_buf_t
        rc = ngx_http_lua_send_special(r, NGX_HTTP_LAST);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_OK;
    }

    /* in != NULL */

    if (ctx->buffering) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua buffering output bufs for the HTTP 1.0 request");

        for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
            ll = &cl->next;
        }

        *ll = in;

        return NGX_OK;
    }

    return ngx_http_lua_output_filter(r, in);
}


/**
 * 发送控制ngx_buf_t
 */
static ngx_int_t
ngx_http_lua_send_special(ngx_http_request_t *r, ngx_uint_t flags)
{
    ngx_int_t            rc;
    ngx_http_request_t  *ar; /* active request */

    ar = r->connection->data;

    if (ar != r) {

        /* bypass ngx_http_postpone_filter_module */

        r->connection->data = r;
        rc = ngx_http_send_special(r, flags);
        r->connection->data = ar;
        return rc;
    }

    return ngx_http_send_special(r, flags);
}


/**
 * 调用ngx_http_output_filter，触发body_filter流程
 */
static ngx_int_t
ngx_http_lua_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t            rc;
    ngx_http_lua_ctx_t  *ctx;
    ngx_http_request_t  *ar; /* active request */

    ar = r->connection->data;

    if (ar != r) {

        /* bypass ngx_http_postpone_filter_module */

        r->connection->data = r;
        rc = ngx_http_output_filter(r, in);
        r->connection->data = ar;
        return rc;
    }

    rc = ngx_http_output_filter(r, in);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx == NULL) {
        return rc;
    }

    ngx_chain_update_chains(r->pool,
                            &ctx->free_bufs, &ctx->busy_bufs, &in,
                            (ngx_buf_tag_t) &ngx_http_lua_module);

    return rc;
}


static ngx_int_t
ngx_http_lua_send_http10_headers(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    off_t                size;
    ngx_chain_t         *cl;
    ngx_int_t            rc;

    if (r->header_sent || ctx->header_sent) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua sending HTTP 1.0 response headers");

    if (r->header_only) {
        goto send;
    }

    if (r->headers_out.content_length == NULL) {
        for (size = 0, cl = ctx->out; cl; cl = cl->next) {
            size += ngx_buf_size(cl->buf);
        }

        r->headers_out.content_length_n = size;
    }

send:

    rc = ngx_http_send_header(r);
    ctx->header_sent = 1;
    return rc;
}


/**
 * ngx_http_lua_new_state->.
 * 
 * 初始化lua registry table。 注册表
 * 
 * registry中保存了多个lua运行期需要保持的变量，例如：cache的lua代码，协程的引用地址等，这些变量如果放在lua堆栈中会被GC机制自动回收，所以需要另外保存。
 * 
 * Lua中的协程也是GC对象，会被系统进行垃圾回收时销毁掉，为了保证挂起的协程不会被GC掉，ngx_http_lua_module在全局的注册表中创建了一个table，
 * 新创建的协程保存在table中，协程执行完毕后从table中注销，GC时就会将已注销的协程回收掉
 * 
 * 注册表创建了几个table，key为ngx_http_lua_coroutines_key的table保存所有的协程
 * 
 * 创建了几个注册表项，分别用于存放协程、Lua的请求ctx、socket连接池、Lua预编译正则表达式对象cache及Lua代码cache
 * 
 */
static void
ngx_http_lua_init_registry(lua_State *L, ngx_log_t *log)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua initializing lua registry");

    //用于存放所有的协程，避免协程对象被GC回收掉，以 ngx_http_lua_coroutines_key 地址作为索引插入注册表
    /* {{{ register a table to anchor lua coroutines reliably:
     * {([int]ref) = [cort]} */
    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                          coroutines_key));
    lua_createtable(L, 0, 32 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /*
     * the the Lua request ctx data table will create in resty.core.ctx,
     * just equivalent to the following code:
     *    lua_pushliteral(L, ngx_http_lua_ctx_tables_key);
     *    lua_createtable(L, 0, 0);
     *    lua_rawset(L, LUA_REGISTRYINDEX);
     */

     // 创建存储 cosocket 连接池信息的 table ，，以 ngx_http_lua_socket_pool_key 地址作为索引插入注册表
    /* create the registry entry for the Lua socket connection pool table */
    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                          socket_pool_key));
    lua_createtable(L, 0, 8 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);

    // 创建存储代码块缓存的 table ，以 ngx_http_lua_code_cache_key 地址作为索引插入注册表
    /* {{{ register table to cache user code:
     * { [(string)cache_key] = <code closure> } */
    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(
                          code_cache_key));
    lua_createtable(L, 0, 8 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}


/**
 * 初始化global全局变量
 * 
 * ngx_http_lua_init->ngx_http_lua_init_vm->ngx_http_lua_new_state->.
 * 主要是注册api ngx.*
 */
static void
ngx_http_lua_init_globals(lua_State *L, ngx_cycle_t *cycle,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua initializing lua globals");

#if defined(NDK) && NDK
    // 注入 ndk api
    ngx_http_lua_inject_ndk_api(L);
#endif /* defined(NDK) && NDK */

    //ngx的各种api和内置变量就是在这里由ngx_http_lua_inject_ngx_api()进行注入，提供给lua脚本调用。
    ngx_http_lua_inject_ngx_api(L, lmcf, log);
}


/**
 * 
 * ngx_http_lua_init->ngx_http_lua_init_vm->ngx_http_lua_new_state->ngx_http_lua_init_globals->.
 * 注入ngx.* API到Lua虚拟机中
 */
static void
ngx_http_lua_inject_ngx_api(lua_State *L, ngx_http_lua_main_conf_t *lmcf,
    ngx_log_t *log)
{
    //ngx
    lua_createtable(L, 0 /* narr */, 115 /* nrec */);    /* ngx.* */

    lua_pushcfunction(L, ngx_http_lua_get_raw_phase_context);
    //ngx._phase_ctx = ngx_http_lua_get_raw_phase_context
    lua_setfield(L, -2, "_phase_ctx");

    //ngx.arg
    ngx_http_lua_inject_arg_api(L);

    //一些常量
    ngx_http_lua_inject_http_consts(L);
    ngx_http_lua_inject_core_consts(L);

    //ngx.log、ngx.print、以及常量ngx.DEBUG等
    ngx_http_lua_inject_log_api(L);
    //ngx.send_headers、ngx.say、ngx.print
    ngx_http_lua_inject_output_api(L);
    //ngx.encode_args、ngx.decode_args、ngx.quote_sql_str
    ngx_http_lua_inject_string_api(L);
    //ngx.redirect、ngx.exec、ngx.on_abort
    ngx_http_lua_inject_control_api(log, L);
    //ngx.location.*
    ngx_http_lua_inject_subrequest_api(L);
    //ngx.sleep
    ngx_http_lua_inject_sleep_api(L);

    //ngx.req.*
    ngx_http_lua_inject_req_api(log, L);
    //ngx.resp.*
    ngx_http_lua_inject_resp_header_api(L);
    //注入ngx ngx.req.get_headers ngx.resp.get_headers 元表方法
    ngx_http_lua_create_headers_metatable(log, L);
    //注入ngx.shared.*相关api
    ngx_http_lua_inject_shdict_api(lmcf, L);
    //注入ngx.socket.tcp.*相关api
    ngx_http_lua_inject_socket_tcp_api(log, L);
    //ngx.socket.udp.*
    ngx_http_lua_inject_socket_udp_api(log, L);
    //ngx.thread.*
    ngx_http_lua_inject_uthread_api(log, L);
    //ngx.timer.*
    ngx_http_lua_inject_timer_api(L);
    //ngx.config.*
    ngx_http_lua_inject_config_api(L);
#if (NGX_THREADS)
    ngx_http_lua_inject_worker_thread_api(log, L);
#endif

    //将package压入栈顶 ;package ngx
    lua_getglobal(L, "package"); /* ngx package */
    //将package.loaded压入栈顶  ; loaded package ngx
    lua_getfield(L, -1, "loaded"); /* ngx package loaded */
    //将ngx压入栈顶 ; ngx loaded package ngx
    lua_pushvalue(L, -3); /* ngx package loaded ngx */
    //package.loaded.ngx=ngx ; loaded package ngx
    lua_setfield(L, -2, "ngx"); /* ngx package loaded */
    //; ngx
    lua_pop(L, 2);

    //将ngx设置为全局变量
    lua_setglobal(L, "ngx");

    //注入协程相关api
    ngx_http_lua_inject_coroutine_api(log, L);
}


#ifdef OPENRESTY_LUAJIT
/**
 * 注入全局写保护，使用全局变量时会得到告警提示
 * 
 */
static void
ngx_http_lua_inject_global_write_guard(lua_State *L, ngx_log_t *log)
{
    int         rc;

    //执行了一段 Lua 代码，设置了 _G 的元表，重载了 __newindex
    const char buf[] =
        "local ngx_log = ngx.log\n"
        "local ngx_WARN = ngx.WARN\n"
        "local tostring = tostring\n"
        "local ngx_get_phase = ngx.get_phase\n"
        "local traceback = require 'debug'.traceback\n"
        "local function newindex(table, key, value)\n"
            "rawset(table, key, value)\n"
            "local phase = ngx_get_phase()\n"
            "if phase == 'init_worker' or phase == 'init' then\n"
                "return\n"
            "end\n"
            "ngx_log(ngx_WARN, 'writing a global Lua variable "
                     "(\\'', tostring(key), '\\') which may lead to "
                     "race conditions between concurrent requests, so "
                     "prefer the use of \\'local\\' variables', "
                     "traceback('', 2))\n"
        "end\n"
        "setmetatable(_G, { __newindex = newindex })\n"
        ;

    rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=_G write guard");

    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to load Lua code (%i): %s",
                      rc, lua_tostring(L, -1));

        lua_pop(L, 1);
        return;
    }

    rc = lua_pcall(L, 0, 0, 0);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to run Lua code (%i): %s",
                      rc, lua_tostring(L, -1));
        lua_pop(L, 1);
    }
}
#endif


void
ngx_http_lua_discard_bufs(ngx_pool_t *pool, ngx_chain_t *in)
{
    ngx_chain_t         *cl;

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
    }
}


ngx_int_t
ngx_http_lua_add_copy_chain(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx,
    ngx_chain_t ***plast, ngx_chain_t *in, ngx_int_t *eof)
{
    ngx_chain_t     *cl;
    size_t           len;
    ngx_buf_t       *b;

    len = 0;
    *eof = 0;

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            len += cl->buf->last - cl->buf->pos;
        }

        if (cl->buf->last_in_chain || cl->buf->last_buf) {
            *eof = 1;
        }
    }

    if (len == 0) {
        return NGX_OK;
    }

    cl = ngx_http_lua_chain_get_free_buf(r->connection->log, r->pool,
                                         &ctx->free_bufs, len);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    dd("chains get free buf: %d == %d", (int) (cl->buf->end - cl->buf->start),
       (int) len);

    b = cl->buf;

    while (in) {
        if (ngx_buf_in_memory(in->buf)) {
            b->last = ngx_copy(b->last, in->buf->pos,
                               in->buf->last - in->buf->pos);
        }

        in = in->next;
    }

    **plast = cl;
    *plast = &cl->next;

    return NGX_OK;
}


/**
 * 重置  ngx_http_lua_ctx_t *ctx
 */
void
ngx_http_lua_reset_ctx(ngx_http_request_t *r, lua_State *L,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua reset ctx");

    ngx_http_lua_finalize_threads(r, ctx, L);

#if 0
    if (ctx->user_co_ctx) {
        /* no way to destroy a list but clean up the whole pool */
        ctx->user_co_ctx = NULL;
    }
#endif

    //重置ctx->entry_co_ctx
    ngx_memzero(&ctx->entry_co_ctx, sizeof(ngx_http_lua_co_ctx_t));

    ctx->entry_co_ctx.next_zombie_child_thread =
        &ctx->entry_co_ctx.zombie_child_threads;

    ctx->entry_co_ctx.co_ref = LUA_NOREF;

    ctx->entered_server_rewrite_phase = 0;
    ctx->entered_rewrite_phase = 0;
    ctx->entered_access_phase = 0;
    ctx->entered_content_phase = 0;

    ctx->exit_code = 0;
    ctx->exited = 0;
    ctx->resume_handler = ngx_http_lua_wev_handler;

    ngx_str_null(&ctx->exec_uri);
    ngx_str_null(&ctx->exec_args);

    ctx->co_op = 0;
}


/**
 * rc = ngx_http_read_client_request_body(r,
                                       ngx_http_lua_generic_phase_post_read);
 */
/* post read callback for rewrite and access phases */
void
ngx_http_lua_generic_phase_post_read(ngx_http_request_t *r)
{
    ngx_http_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua post read for rewrite/access phases");

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    r->main->count--;

    if (ctx == NULL) {
        return;
    }

    ctx->read_body_done = 1;

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}


/**
 * ctx->cleanup
 * 
 * 注册到r->pool上的cleanup_handler
 */
void
ngx_http_lua_request_cleanup_handler(void *data)
{
    ngx_http_lua_ctx_t          *ctx = data;

    ngx_http_lua_request_cleanup(ctx, 0 /* forcible */);
}


void
ngx_http_lua_request_cleanup(ngx_http_lua_ctx_t *ctx, int forcible)
{
    lua_State                   *L;
    ngx_http_request_t          *r;
    ngx_http_lua_main_conf_t    *lmcf;

    /*  force coroutine handling the request quit */
    if (ctx == NULL) {
        dd("ctx is NULL");
        return;
    }

    r = ctx->request;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua request cleanup: forcible=%d", forcible);

    if (ctx->cleanup) {
        *ctx->cleanup = NULL;
        ctx->cleanup = NULL;
    }

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

#if 1
    if (r->connection->fd == (ngx_socket_t) -1) {
        /* being a fake request */

        if (ctx->context == NGX_HTTP_LUA_CONTEXT_TIMER) {
            /* being a timer handler */
            lmcf->running_timers--;
        }
    }
#endif

    L = ngx_http_lua_get_lua_vm(r, ctx);

    ngx_http_lua_finalize_threads(r, ctx, L);
}


/*
 * description:
 *  run a Lua coroutine specified by ctx->cur_co_ctx->co
 * return value:
 *  NGX_AGAIN:      I/O interruption: r->main->count intact
 *  NGX_DONE:       I/O interruption: r->main->count already incremented by 1
 *  NGX_ERROR:      error
 *  >= 200          HTTP status code
 */
/**
 * 当前待执行的协程 ctx->cur_co_ctx->co
 * 
 * http://www.qlee.in/openresty/2017/03/07/nginx-lua-coroutine-scheduler-6/
 * 
 * 负责运行一个 Lua 协程, 调用lua_resume
 * 
 * 返回NGX_ERROR或大于200的HTTP状态码: 将会无条件结束当前请求的处理
 * 返回NGX_OK:当前阶段处理完成(子协程和运行在内的所有 light thread 都结束），此时只需要调用 ngx_http_lua_send_chain_link 发送响应即可
 * 返回NGX_AGAIN: 子协程未结束，继续等待下次唤醒重入
 * 
 * 重点关注的是NGX_AGAIN和NGX_DONE这两个。返回这两个值时都要调用ngx_http_lua_run_posted_thread来处理
 * 
 * ngx_http_lua_run_thread什么时候会返回NGX_AGAIN?
 *  1.ngx.sleep或ngx.socket等导致协程的yield
 *  2.调用ngx.thread导致当前请求对应的一个父协程和一个或多个”light thread”没有全部退出。 
 *    由于情况2的存在，需要调用ngx_http_lua_run_posted_thread进行处理。
 * 
 *  nrets: lua里导致yield后，重新开始执行的方法的返回参数的个数
 */
ngx_int_t
ngx_http_lua_run_thread(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, volatile int nrets)
{
    ngx_http_lua_co_ctx_t   *next_coctx, *parent_coctx, *orig_coctx;
    int                      rv, success = 1;
    lua_State               *next_co;
    lua_State               *old_co;
    const char              *err, *msg, *trace;
    ngx_int_t                rc;
#if (NGX_PCRE)
    ngx_pool_t              *old_pool = NULL;
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread, top:%d c:%ud", lua_gettop(L),
                   r->main->count);

    //函数的准备工作，设置一个当 Lua VM 抛出异常时进行处理的回调函数
    /* set Lua VM panic handler */
    lua_atpanic(L, ngx_http_lua_atpanic);

    //try-catch
    NGX_LUA_EXCEPTION_TRY {

        /*
         * silence a -Werror=clobbered warning with gcc 5.4
         * due to above setjmp
         */
        err = NULL;
        msg = NULL;
        trace = NULL;

        if (ctx->cur_co_ctx->thread_spawn_yielded) {
            ngx_http_lua_probe_info("thread spawn yielded");

            ctx->cur_co_ctx->thread_spawn_yielded = 0;
            nrets = 1;
        }

        //调度循环，先从ctx->cur_co_ctx获取下一个待resume的协程上下文，然后lua_resume()执行或恢复该协程
        for ( ;; ) {

            dd("ctx: %p, co: %p, co status: %d, co is_wrap: %d",
               ctx, ctx->cur_co_ctx->co, ctx->cur_co_ctx->co_status,
               ctx->cur_co_ctx->is_wrap);

#if (NGX_PCRE)
            /* XXX: work-around to nginx regex subsystem */
            old_pool = ngx_http_lua_pcre_malloc_init(r->pool);
#endif

            orig_coctx = ctx->cur_co_ctx;

#ifdef NGX_LUA_USE_ASSERT
            dd("%p: saved co top: %d, nrets: %d, true top: %d",
               orig_coctx->co,
               (int) orig_coctx->co_top, (int) nrets,
               (int) lua_gettop(orig_coctx->co));
#endif

#if DDEBUG
            if (lua_gettop(orig_coctx->co) > 0) {
                dd("co top elem: %s", luaL_typename(orig_coctx->co, -1));
            }

            if (orig_coctx->propagate_error) {
                dd("co propagate_error: %d", orig_coctx->propagate_error);
            }
#endif

            if (orig_coctx->propagate_error) {
                orig_coctx->propagate_error = 0;
                goto propagate_error;
            }

            ngx_http_lua_assert(orig_coctx->co_top + nrets
                                == lua_gettop(orig_coctx->co));

            //恢复 ctx->cur_co_ctx 协程的执行
            //利用 lua_resume 来运行目标协程，需要运行的函数及其参数在调用 ngx_http_lua_run_thread  前就已经压到目标协程虚拟机的栈之上了
            rv = lua_resume(orig_coctx->co, nrets);

#if (NGX_PCRE)
            /* XXX: work-around to nginx regex subsystem */
            ngx_http_lua_pcre_malloc_done(old_pool);
#endif

#if 0
            /* test the longjmp thing */
            if (rand() % 2 == 0) {
                NGX_LUA_EXCEPTION_THROW(1);
            }
#endif

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua resume returned %d", rv);

            //switch resume 结果， 其返回值LUA_YIELD表示协程挂起，0表示协程执行结束，其余的表示协程出错了
            switch (rv) {
            case LUA_YIELD:
                //返回码是 LUA_YIELD，说明目标协程没有运行完，主动调用了yield。
                /*  yielded, let event handler do the rest job */
                /*  FIXME: add io cmd dispatcher here */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua thread yielded");

#ifdef NGX_LUA_USE_ASSERT
                dd("%p: saving curr top after yield: %d (co-op: %d)",
                   orig_coctx->co,
                   (int) lua_gettop(orig_coctx->co), (int) ctx->co_op);
                orig_coctx->co_top = lua_gettop(orig_coctx->co);
#endif

                //以下三种情况都不需要协程继续运行了，退出执行相应的处理
                
                //使用 ngx.exit, ngx.exec, ngx.redirect 可以直接跳出协程，而不用等待子协程处理完成。

                //为true表明调用了ngx.redirect.
                //ngx.redirect("/foo", 301) 	-- 重定向，终止的当前请求的处理，即不再处理后续阶段
                if (r->uri_changed) {
                    return ngx_http_lua_handle_rewrite_jump(L, r, ctx);
                }

                //为true表明调用了ngx.exit
                //ngx.exit 可接受多种参数：
                //ngx.exit(ngx.OK) 		-- 完成当前阶段（退出子协程），继续下一个阶段
                //ngx.exit(ngx.ERROR)		-- 中断当前请求，报错
                //ngx.exit(HTTP_STATUS)	-- 结束 content 阶段，继续下个阶段
                if (ctx->exited) {
                    return ngx_http_lua_handle_exit(L, r, ctx);
                }

                //为true表明调用了ngx.exec
                //ngx.exec("/a/b/c") 			-- 内部跳转，直接从子协程结束，回到主协程
                if (ctx->exec_uri.len) {
                    return ngx_http_lua_handle_exec(L, r, ctx);
                }

                /*
                 * check if coroutine.resume or coroutine.yield called
                 * lua_yield()
                 */
                //协程挂起又分为四种不同的情况：即等待I/O、新建thread、coroutine.resume()和coroutine.yield()。根据不同的情况，决定是跳到循环前面继续恢复下一个协程，还是返回上层函数
                //检查是进行了什么操作导致 yield 的
                // 判断是否 coroutine.resume 或者 coroutine.yield 被调用的情况
                switch (ctx->co_op) {

                case NGX_HTTP_LUA_USER_CORO_NOP:            //退出循环
                    //ngx.socket 和 ngx.sleep 导致。表示不再有协程需要处理了，跳出这一次循环，等待下一次的读写时间，或者定时器到期
                    dd("hit! it is the API yield");

                     //不再有线程需要处理了，跳出这一次循环，重新等待下一次读写事件。
                    ngx_http_lua_assert(lua_gettop(ctx->cur_co_ctx->co) == 0);

                    //接下来没有需要执行的协程了，等待 event 调度吧
                    ctx->cur_co_ctx = NULL;

                    return NGX_AGAIN;

                case NGX_HTTP_LUA_USER_THREAD_RESUME:       //继续循环

                    //调用ngx.thread.spawn 导致，ctx->cur_co_ctx 已经在接口里面设置过了，不用再设置了。
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "lua user thread resume");

                    ctx->co_op = NGX_HTTP_LUA_USER_CORO_NOP;
                    nrets = lua_gettop(ctx->cur_co_ctx->co) - 1;
                    dd("nrets = %d", nrets);

#ifdef NGX_LUA_USE_ASSERT
                    /* ignore the return value (the thread) already pushed */
                    orig_coctx->co_top--;
#endif

                    break;

                case NGX_HTTP_LUA_USER_CORO_RESUME:         //继续循环
                    //调用coroutine.resume 导致，ctx->cur_co_ctx 已经在接口里面设置过了，不用再设置了。
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "lua coroutine: resume");

                    /*
                     * the target coroutine lies at the base of the
                     * parent's stack
                     */
                    ctx->co_op = NGX_HTTP_LUA_USER_CORO_NOP;

                    old_co = ctx->cur_co_ctx->parent_co_ctx->co;

                    nrets = lua_gettop(old_co);
                    if (nrets) {
                        dd("moving %d return values to parent", nrets);
                        lua_xmove(old_co, ctx->cur_co_ctx->co, nrets);

#ifdef NGX_LUA_USE_ASSERT
                        ctx->cur_co_ctx->parent_co_ctx->co_top -= nrets;
#endif
                    }

                    break;

                default:
                    //coroutine.yield被调用 导致
                    /* ctx->co_op == NGX_HTTP_LUA_USER_CORO_YIELD */

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "lua coroutine: yield");

                    ctx->co_op = NGX_HTTP_LUA_USER_CORO_NOP;

                    if (ngx_http_lua_is_thread(ctx)) {
                        ngx_http_lua_probe_thread_yield(r, ctx->cur_co_ctx->co);

                        /* discard any return values from user
                         * coroutine.yield()'s arguments */
                        // coroutine.yield() 的调用参数都被丢弃了，不会被传到 resume 
                        lua_settop(ctx->cur_co_ctx->co, 0);

#ifdef NGX_LUA_USE_ASSERT
                        ctx->cur_co_ctx->co_top = 0;
#endif

                        ngx_http_lua_probe_info("set co running");
                        ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

                        // 判断有没有需要后处理的线程，排队等待处理
                        if (ctx->posted_threads) {
                            ngx_http_lua_post_thread(r, ctx, ctx->cur_co_ctx);
                            ctx->cur_co_ctx = NULL;
                            return NGX_AGAIN;
                        }

                        /* no pending threads, so resume the thread
                         * immediately */

                        // 如果木有，直接让自己恢复执行即可，直接回到 for 循环开头
                        nrets = 0;
                        continue;
                    }

                    /* being a user coroutine that has a parent */

                    // 下面的代码是 切换当前线程 到 父线程 的逻辑
                    nrets = lua_gettop(ctx->cur_co_ctx->co);

                    //父协程作为下一次要执行的协程
                    next_coctx = ctx->cur_co_ctx->parent_co_ctx;
                    next_co = next_coctx->co;

                    if (nrets) {
                        dd("moving %d return values to next co", nrets);
                        lua_xmove(ctx->cur_co_ctx->co, next_co, nrets);
#ifdef NGX_LUA_USE_ASSERT
                        ctx->cur_co_ctx->co_top -= nrets;
#endif
                    }

                    if (!ctx->cur_co_ctx->is_wrap) {
                        /*
                         * prepare return values for coroutine.resume
                         * (true plus any retvals)
                         */
                        // 在 coroutine.resume 调用者线程的栈上插入一个返回值 true
                        lua_pushboolean(next_co, 1);
                        lua_insert(next_co, 1);
                        nrets++;  /* add the true boolean value */
                    }

                    //设置成下一次要执行的协程
                    ctx->cur_co_ctx = next_coctx;

                    break;
                }

                /* try resuming on the new coroutine again */
                continue;

            case 0:
                //协程执行结束了

                //清理 pending 的操作
                ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

                ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

                //设置状态为 DEAD
                ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

                //如果有僵尸子协程，则进行清理
                if (ctx->cur_co_ctx->zombie_child_threads) {
                    ngx_http_lua_cleanup_zombie_child_uthreads(r, L, ctx,
                                                               ctx->cur_co_ctx);
                }

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua light thread ended normally");

                //如果是入口协程，则删除协程
                if (ngx_http_lua_is_entry_thread(ctx)) {

                    lua_settop(L, 0);

                    ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);

                    dd("uthreads: %d", (int) ctx->uthreads);

                    //如果还有用户线程
                    if (ctx->uthreads) {

                        ctx->cur_co_ctx = NULL;
                        return NGX_AGAIN;
                    }

                    /* all user threads terminated already */
                    goto done;      //return NGX_OK;
                }

                //如果是用户协程
                if (ctx->cur_co_ctx->is_uthread) {
                    /* being a user thread */

                    lua_settop(L, 0);

                    //获取到父协程
                    parent_coctx = ctx->cur_co_ctx->parent_co_ctx;

                    //如果父协程还存活
                    if (ngx_http_lua_coroutine_alive(parent_coctx)) {
                        //是否正在被父协程 wait
                        if (ctx->cur_co_ctx->waited_by_parent) {
                            ngx_http_lua_probe_info("parent already waiting");
                            ctx->cur_co_ctx->waited_by_parent = 0;
                            success = 1;
                            goto user_co_done;
                        }

                        ngx_http_lua_probe_info("parent still alive");

                        //没有被父协程 wait，加入到僵尸协程中
                        if (ngx_http_lua_post_zombie_thread(r, parent_coctx,
                                                            ctx->cur_co_ctx)
                            != NGX_OK)
                        {
                            return NGX_ERROR;
                        }

                        lua_pushboolean(ctx->cur_co_ctx->co, 1);
                        lua_insert(ctx->cur_co_ctx->co, 1);

                        ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_ZOMBIE;
                        ctx->cur_co_ctx = NULL;
                        return NGX_AGAIN;
                    }
                    /** 父协程也不存在了 */

                    //删除协程
                    ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                    ctx->uthreads--;

                    if (ctx->uthreads == 0) {
                        if (ngx_http_lua_entry_thread_alive(ctx)) {
                            ctx->cur_co_ctx = NULL;
                            return NGX_AGAIN;
                        }

                        /* all threads terminated already */
                        goto done;
                    }

                    /* some other user threads still running */
                    ctx->cur_co_ctx = NULL;
                    return NGX_AGAIN;
                }

                /** 协程属于存在父协程的子协程 */

                /* being a user coroutine that has a parent */

                success = 1;

user_co_done:   //子协程执行结束，父协程正在wait子协程

                nrets = lua_gettop(ctx->cur_co_ctx->co);

                //把父协程设置为接下来要执行的协程
                next_coctx = ctx->cur_co_ctx->parent_co_ctx;

                if (next_coctx == NULL) {
                    /* being a light thread */
                    goto no_parent;
                }

                next_co = next_coctx->co;

                if (nrets) {
                    //将返回值移动到父协程栈上
                    lua_xmove(ctx->cur_co_ctx->co, next_co, nrets);
                }

                //销毁当前子协程
                if (ctx->cur_co_ctx->is_uthread) {
                    ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                    ctx->uthreads--;
                }

                if (!ctx->cur_co_ctx->is_wrap) {
                    /*
                     * ended successfully, coroutine.resume returns true plus
                     * any return values
                     */
                    lua_pushboolean(next_co, success);
                    lua_insert(next_co, 1);
                    nrets++;
                }

                //把父协程设置为接下来要执行的协程
                //next_coctx为当前协程的父协程
                ctx->cur_co_ctx = next_coctx;

                ngx_http_lua_probe_info("set parent running");

                next_coctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua coroutine: lua user thread ended normally");

                continue;

                //其他情况都表示运行出错
            case LUA_ERRRUN:
                //运行时错误
                err = "runtime error";
                break;

            case LUA_ERRSYNTAX:
                //Lua 代码存在语法错误
                err = "syntax error";
                break;

            case LUA_ERRMEM:
                //内存分配错误
                err = "[lua] memory allocation error";
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, err);
                abort();
                break;

            case LUA_ERRERR:
                //错误处理程序出错
                err = "error handler error";
                break;

            default:
                //未知错误
                err = "unknown error";
                break;
            }

            if (ctx->cur_co_ctx != orig_coctx) {
                ctx->cur_co_ctx = orig_coctx;
            }

            //清理 pending 操作
            ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

            ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 0);

            ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

            if (orig_coctx->is_uthread
                || orig_coctx->is_wrap
                || ngx_http_lua_is_entry_thread(ctx))
            {
                ngx_http_lua_thread_traceback(L, orig_coctx->co, orig_coctx);
                trace = lua_tostring(L, -1);

                if (lua_isstring(orig_coctx->co, -1)) {
                    msg = lua_tostring(orig_coctx->co, -1);
                    dd("user custom error msg: %s", msg);

                } else {
                    msg = "unknown reason";
                }
            }

propagate_error:

            if (ctx->cur_co_ctx->is_uthread) {
                ngx_http_lua_assert(err != NULL && msg != NULL
                                    && trace != NULL);

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "lua user thread aborted: %s: %s\n%s",
                              err, msg, trace);

                lua_settop(L, 0);

                parent_coctx = ctx->cur_co_ctx->parent_co_ctx;

                if (ngx_http_lua_coroutine_alive(parent_coctx)) {
                    if (ctx->cur_co_ctx->waited_by_parent) {
                        ctx->cur_co_ctx->waited_by_parent = 0;
                        success = 0;
                        goto user_co_done;
                    }

                    if (ngx_http_lua_post_zombie_thread(r, parent_coctx,
                                                        ctx->cur_co_ctx)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    lua_pushboolean(ctx->cur_co_ctx->co, 0);
                    lua_insert(ctx->cur_co_ctx->co, 1);

                    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_ZOMBIE;
                    ctx->cur_co_ctx = NULL;
                    return NGX_AGAIN;
                }

                ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                ctx->uthreads--;

                if (ctx->uthreads == 0) {
                    if (ngx_http_lua_entry_thread_alive(ctx)) {
                        ctx->cur_co_ctx = NULL;
                        return NGX_AGAIN;
                    }

                    /* all threads terminated already */
                    goto done;
                }

                /* some other user threads still running */
                ctx->cur_co_ctx = NULL;
                return NGX_AGAIN;
            }

            if (ngx_http_lua_is_entry_thread(ctx)) {
                ngx_http_lua_assert(err != NULL && msg != NULL
                                    && trace != NULL);

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "lua entry thread aborted: %s: %s\n%s",
                              err, msg, trace);

                lua_settop(L, 0);

                /* being the entry thread aborted */

                if (r->filter_finalize) {
                    ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
                }

                ngx_http_lua_request_cleanup(ctx, 0);

                dd("headers sent? %d", r->header_sent || ctx->header_sent);

                if (ctx->no_abort) {
                    ctx->no_abort = 0;
                    return NGX_ERROR;
                }

                return (r->header_sent || ctx->header_sent) ? NGX_ERROR :
                       NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* being a user coroutine that has a parent */

            next_coctx = ctx->cur_co_ctx->parent_co_ctx;
            if (next_coctx == NULL) {
                goto no_parent;
            }

            next_co = next_coctx->co;

            ngx_http_lua_probe_info("set parent running");

            next_coctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

            ctx->cur_co_ctx = next_coctx;

            if (orig_coctx->is_wrap) {
                /*
                 * coroutine.wrap propagates errors
                 * to its parent coroutine
                 */
                next_coctx->propagate_error = 1;
                continue;
            }

            /*
             * ended with error, coroutine.resume returns false plus
             * err msg
             */
            lua_pushboolean(next_co, 0);
            lua_xmove(orig_coctx->co, next_co, 1);
            nrets = 2;

            /* try resuming on the new coroutine again */
            continue;
        }

    } NGX_LUA_EXCEPTION_CATCH {
        dd("nginx execution restored");
    }

    return NGX_ERROR;

no_parent:

    lua_settop(L, 0);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 0);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "lua handler aborted: "
                  "user coroutine has no parent");

    return (r->header_sent || ctx->header_sent) ?
                NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR;

done:

    if (ctx->entered_content_phase
        && r->connection->fd != (ngx_socket_t) -1)
    {
        rc = ngx_http_lua_send_chain_link(r, ctx,
                                          NULL /* last_buf */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

    return NGX_OK;
}


/**
 * ctx->resume_handler = ngx_http_lua_wev_handler;
 * 
 */
ngx_int_t
ngx_http_lua_wev_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_event_t                 *wev;
    ngx_connection_t            *c;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_core_loc_conf_t    *clcf;

    ngx_http_lua_socket_tcp_upstream_t *u;

    c = r->connection;
    wev = c->write;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "lua run write event handler: timedout:%ud, ready:%ud, "
                   "writing_raw_req_socket:%ud",
                   wev->timedout, wev->ready, ctx->writing_raw_req_socket);

    clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

    if (wev->timedout && !ctx->writing_raw_req_socket) {
        if (!wev->delayed) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

            goto flush_coros;
        }

        wev->timedout = 0;
        wev->delayed = 0;

        if (!wev->ready) {
            ngx_add_timer(wev, clcf->send_timeout);

            //将可写事件监听加入epoll
            if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
                if (ctx->entered_content_phase) {
                    ngx_http_lua_finalize_request(r, NGX_ERROR);
                }
                return NGX_ERROR;
            }
        }
    }

    if (!wev->ready && !wev->timedout) {
        goto useless;
    }

    if (ctx->writing_raw_req_socket) {
        ctx->writing_raw_req_socket = 0;

        u = ctx->downstream;
        if (u == NULL) {
            return NGX_ERROR;
        }

        u->write_event_handler(r, u);
        return NGX_DONE;
    }

    if (c->buffered & (NGX_HTTP_LOWLEVEL_BUFFERED | NGX_LOWLEVEL_BUFFERED)) {
        rc = ngx_http_lua_flush_pending_output(r, ctx);

        dd("flush pending output returned %d, c->error: %d", (int) rc,
           c->error);

        if (rc != NGX_ERROR && rc != NGX_OK) {
            goto useless;
        }

        /* when rc == NGX_ERROR, c->error must be set */
    }

flush_coros:

    dd("ctx->flushing_coros: %d", (int) ctx->flushing_coros);

    if (ctx->flushing_coros) {
        return ngx_http_lua_process_flushing_coroutines(r, ctx);
    }

    /* ctx->flushing_coros == 0 */

useless:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "useless lua write event handler");

    if (ctx->entered_content_phase) {
        return NGX_OK;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_lua_process_flushing_coroutines(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t                    rc, n;
    ngx_uint_t                   i;
    ngx_list_part_t             *part;
    ngx_http_lua_co_ctx_t       *coctx;

    dd("processing flushing coroutines");

    coctx = &ctx->entry_co_ctx;
    n = ctx->flushing_coros;

    if (coctx->flushing) {
        coctx->flushing = 0;

        ctx->flushing_coros--;
        n--;
        ctx->cur_co_ctx = coctx;

        rc = ngx_http_lua_flush_resume_helper(r, ctx);
        if (rc == NGX_ERROR || rc >= NGX_OK) {
            return rc;
        }

        /* rc == NGX_DONE */
    }

    if (n) {

        if (ctx->user_co_ctx == NULL) {
            return NGX_ERROR;
        }

        part = &ctx->user_co_ctx->part;
        coctx = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                coctx = part->elts;
                i = 0;
            }

            if (coctx[i].flushing) {
                coctx[i].flushing = 0;
                ctx->flushing_coros--;
                n--;
                ctx->cur_co_ctx = &coctx[i];

                rc = ngx_http_lua_flush_resume_helper(r, ctx);
                if (rc == NGX_ERROR || rc >= NGX_OK) {
                    return rc;
                }

                /* rc == NGX_DONE */

                if (n == 0) {
                    return NGX_DONE;
                }
            }
        }
    }

    if (n) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_lua_flush_pending_output(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t           rc;
    ngx_chain_t        *cl;
    ngx_event_t        *wev;
    ngx_connection_t   *c;

    ngx_http_core_loc_conf_t    *clcf;

    c = r->connection;
    wev = c->write;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "lua flushing output: buffered 0x%uxd",
                   c->buffered);

    if (ctx->busy_bufs) {
        /* FIXME since cosockets also share this busy_bufs chain, this condition
         * might not be strong enough. better use separate busy_bufs chains. */
        rc = ngx_http_lua_output_filter(r, NULL);

    } else {
        cl = ngx_http_lua_get_flush_chain(r, ctx);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_http_lua_output_filter(r, cl);
    }

    dd("output filter returned %d", (int) rc);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (c->buffered & (NGX_HTTP_LOWLEVEL_BUFFERED | NGX_LOWLEVEL_BUFFERED)) {

        clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            if (ctx->entered_content_phase) {
                ngx_http_lua_finalize_request(r, NGX_ERROR);
            }

            return NGX_ERROR;
        }

        if (ctx->flushing_coros) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "lua flush still waiting: buffered 0x%uxd",
                           c->buffered);

            return NGX_DONE;
        }

    } else {
#if 1
        if (wev->timer_set && !wev->delayed) {
            ngx_del_timer(wev);
        }
#endif
    }

    return NGX_OK;
}


/**
 * 计算hex_md5
 * *buf和buf_len为要计算的字符串
 * *dest为md5值输出位置
 */
u_char *
ngx_http_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len)
{
    ngx_md5_t                     md5;
    u_char                        md5_buf[MD5_DIGEST_LENGTH];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, buf, buf_len);
    ngx_md5_final(md5_buf, &md5);

    return ngx_hex_dump(dest, md5_buf, sizeof(md5_buf));
}


/**
 * 对于以下情况：
 *  Foo: abc
 *  Foo: def
 *  Foo: xyz
 * 
 * ngx.req.get_headers()["Foo"] 返回的时候 {"abc", "def", "xyz"}
 * 
 * 由此函数实现
 * 
 * 先尝试访问下目标表 t1 里对应的 k1，如果得到的值 v2 为 nil，简单地把 v1 设置进去即可；
 * 如果 v2 不是 nil，说明 k1 重复了，需要整合为表，
 *      此时，如果 v2 不是一个表，那么只需创建一个表 t2，然后将 t2[1] 设置为 v2、t2[2] 设置为 v1；
 *      如果 v2 本身就是一个表了，那么只要把 v1 放到这个表 v2 的最后（数组部分）
 * 
 */
void
ngx_http_lua_set_multi_value_table(lua_State *L, int index)
{
    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    lua_pushvalue(L, -2); /* stack: table key value key */
    lua_rawget(L, index);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1); /* stack: table key value */
        lua_rawset(L, index); /* stack: table */

    } else {
        if (!lua_istable(L, -1)) {
            /* just inserted one value */
            lua_createtable(L, 4, 0);
                /* stack: table key value value table */
            lua_insert(L, -2);
                /* stack: table key value table value */
            lua_rawseti(L, -2, 1);
                /* stack: table key value table */
            lua_insert(L, -2);
                /* stack: table key table value */

            lua_rawseti(L, -2, 2); /* stack: table key table */

            lua_rawset(L, index); /* stack: table */

        } else {
            /* stack: table key value table */
            lua_insert(L, -2); /* stack: table key table value */

            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
                /* stack: table key table  */
            lua_pop(L, 2); /* stack: table */
        }
    }
}


/**
 * uri编码，当dst为null时，只是计算需要转义的字符个数
 */
uintptr_t
ngx_http_lua_escape_uri(u_char *dst, u_char *src, size_t size, ngx_uint_t type)
{
    ngx_uint_t      n;
    uint32_t       *escape;
    static u_char   hex[] = "0123456789ABCDEF";

                    /* " ", "#", "%", "?", %00-%1F, %7F-%FF */

    static uint32_t   uri[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x80000029, /* 1000 0000 0000 0000  0000 0000 0010 1001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "#", "%", "+", "?", %00-%1F, %7F-%FF */

    static uint32_t   args[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x80000829, /* 1000 0000 0000 0000  0000 1000 0010 1001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* not ALPHA, DIGIT, "-", ".", "_", "~" */

    static uint32_t   uri_component[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0xfc00987d, /* 1111 1100 0000 0000  1001 1000 0111 1101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "#", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   html[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x000000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   refresh[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000085, /* 0000 0000 0000 0000  0000 0000 1000 0101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "%", %00-%1F */

    static uint32_t   memcached[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };

                    /* mail_auth is the same as memcached */

                    /* " ", """, "(", ")", ",", "/", ":", ";", "?",
                     * "<", "=", ">", "?", "@", "[", "]", "\", "{",
                     * "}", %00-%1F, %7F-%FF
                     */

    static uint32_t   header_name[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0xfc009305, /* 1111 1100 0000 0000  1001 0011 0000 0101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x38000001, /* 0011 1000 0000 0000  0000 0000 0000 0001 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0xa8000000, /* 1010 1000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* "%00-%08, %0A-%0F, %7F */

    static uint32_t   header_value[] = {
        0xfffffdff, /* 1111 1111 1111 1111  1111 1101 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };

    static uint32_t  *map[] =
        { uri, args, uri_component, html, refresh, memcached, memcached,
          header_name, header_value };

    escape = map[type];

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


static int
ngx_http_lua_util_hex2int(char xdigit)
{
    if (isdigit(xdigit)) {
        return xdigit - '0';
    }

    xdigit = tolower(xdigit);
    if (xdigit <= 'f' && xdigit >= 'a') {
        return xdigit - 'a' + 10;
    }

    return -1;
}


/**
 * uri解码，解码过程中dst会被移动，所以该方法执行结束后，检查dst位置，就可以知道解码后的长度
 */
/* XXX we also decode '+' to ' ' */
void
ngx_http_lua_unescape_uri(u_char **dst, u_char **src, size_t size,
    ngx_uint_t type)
{
    u_char *d = *dst, *s = *src, *de = (*dst + size);
    int     isuri = type & NGX_UNESCAPE_URI;
    int     isredirect = type & NGX_UNESCAPE_REDIRECT;

    while (size--) {
        u_char curr = *s++;

        if (curr == '?' &&
            (type & (NGX_UNESCAPE_URI | NGX_UNESCAPE_REDIRECT)))
        {
            *d++ = '?';
            break;

        } else if (curr == '%') {
            u_char ch;
            if (size < 2 || !(isxdigit(s[0]) && isxdigit(s[1]))) {
                *d++ = '%';
                continue;
            }
            /* we can be sure here they must be hex digits */
            ch = ngx_http_lua_util_hex2int(s[0]) * 16 +
                 ngx_http_lua_util_hex2int(s[1]);

            if ((isuri || isredirect) && ch == '?') {
                *d++ = ch;
                break;

            } else if (isredirect && (ch <= '%' || ch >= 0x7f)) {
                *d++ = '%';
                continue;
            }

            *d++ = ch;
            s += 2;
            size -= 2;

        } else if (curr == '+') {
            *d++ = ' ';
            continue;

        } else {
            *d++ = curr;
        }
    }

    /* a safe guard if dst need to be null-terminated */
    if (d != de) {
        *d = '\0';
    }

    *dst = d;
    *src = s;
}


/**
 * ngx.req相关api注入
 */
void
ngx_http_lua_inject_req_api(ngx_log_t *log, lua_State *L)
{
    /* ngx.req table */

    lua_createtable(L, 0 /* narr */, 23 /* nrec */);    /* .req */

    //ngx.req.set_header/raw_header/http_version
    ngx_http_lua_inject_req_header_api(L);
    //ngx.req.set_uri
    ngx_http_lua_inject_req_uri_api(log, L);
    //ngx.req.set_uri_args/ngx.req.get_post_args
    ngx_http_lua_inject_req_args_api(L);
    //ngx.req.body
    ngx_http_lua_inject_req_body_api(L);
    //ngx.req.socket
    ngx_http_lua_inject_req_socket_api(L);
    //ngx.req.is_internal
    ngx_http_lua_inject_req_misc_api(L);

    lua_setfield(L, -2, "req");
}


/**
 * lua代码里调用了 ngx.exec(), 导致lua代码yield
 * 
 * ngx.exec("/a/b/c") 			-- 内部跳转，直接从子协程结束，回到主协程
 */
static ngx_int_t
ngx_http_lua_handle_exec(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t               rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread initiated internal redirect to %V",
                   &ctx->exec_uri);

    ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 1 /* forcible */);

    if (ctx->exec_uri.data[0] == '@') {
        if (ctx->exec_args.len > 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "query strings %V ignored when exec'ing "
                          "named location %V",
                          &ctx->exec_args, &ctx->exec_uri);
        }

        r->write_event_handler = ngx_http_request_empty_handler;

#if 1
        if (r->read_event_handler == ngx_http_lua_rd_check_broken_connection) {
            /* resume the read event handler */

            r->read_event_handler = ngx_http_block_reading;
        }
#endif

#if 1
        /* clear the modules contexts */
        ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
#endif

        rc = ngx_http_named_location(r, &ctx->exec_uri);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

#if 0
        if (!ctx->entered_content_phase) {
            /* XXX ensure the main request ref count
             * is decreased because the current
             * request will be quit */
            r->main->count--;
            dd("XXX decrement main count: c:%d", (int) r->main->count);
        }
#endif

        return NGX_DONE;
    }

    dd("internal redirect to %.*s", (int) ctx->exec_uri.len,
       ctx->exec_uri.data);

    r->write_event_handler = ngx_http_request_empty_handler;

    if (r->read_event_handler == ngx_http_lua_rd_check_broken_connection) {
        /* resume the read event handler */

        r->read_event_handler = ngx_http_block_reading;
    }

    rc = ngx_http_internal_redirect(r, &ctx->exec_uri, &ctx->exec_args);

    dd("internal redirect returned %d when in content phase? "
       "%d", (int) rc, ctx->entered_content_phase);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

#if 0
    if (!ctx->entered_content_phase) {
        /* XXX ensure the main request ref count
         * is decreased because the current
         * request will be quit */
        dd("XXX decrement main count");
        r->main->count--;
    }
#endif

    return NGX_DONE;
}


/**
 * lua代码里执行ngx.exit,导致lua代码yield
 * 
    ngx.exit 可接受多种参数：
    ngx.exit(ngx.OK) 		-- 完成当前阶段（退出子协程），继续下一个阶段
    ngx.exit(ngx.ERROR)		-- 中断当前请求，报错
    ngx.exit(HTTP_STATUS)	-- 结束 content 阶段，继续下个阶段
 */
static ngx_int_t
ngx_http_lua_handle_exit(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t           rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread aborting request with status %d",
                   ctx->exit_code);

    ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 0);

    if (r->connection->fd == (ngx_socket_t) -1) {  /* fake request */
        return ctx->exit_code;
    }

#if 1
    if (!r->header_sent
        && !ctx->header_sent
        && r->headers_out.status == 0
        && ctx->exit_code >= NGX_HTTP_OK)
    {
        r->headers_out.status = ctx->exit_code;
    }
#endif

    if (ctx->buffering
        && r->headers_out.status
        && ctx->exit_code != NGX_ERROR
        && ctx->exit_code != NGX_HTTP_REQUEST_TIME_OUT
        && ctx->exit_code != NGX_HTTP_CLIENT_CLOSED_REQUEST
        && ctx->exit_code != NGX_HTTP_CLOSE)
    {
        rc = ngx_http_lua_send_chain_link(r, ctx, NULL /* indicate last_buf */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (ctx->exit_code >= NGX_HTTP_OK) {
            return NGX_HTTP_OK;
        }

        return ctx->exit_code;
    }

    if ((ctx->exit_code == NGX_OK
         && ctx->entered_content_phase)
        || (ctx->exit_code >= NGX_HTTP_OK
            && ctx->exit_code < NGX_HTTP_SPECIAL_RESPONSE
            && ctx->exit_code != NGX_HTTP_NO_CONTENT))
    {
        rc = ngx_http_lua_send_chain_link(r, ctx, NULL /* indicate last_buf */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

#if 1
    if ((r->header_sent || ctx->header_sent)
        && ctx->exit_code > NGX_OK
        && ctx->exit_code != NGX_HTTP_REQUEST_TIME_OUT
        && ctx->exit_code != NGX_HTTP_CLIENT_CLOSED_REQUEST
        && ctx->exit_code != NGX_HTTP_CLOSE)
    {
        if (ctx->entered_content_phase) {
            return NGX_OK;
        }

        return NGX_HTTP_OK;
    }
#endif

    return ctx->exit_code;
}


/**
 * set_uri_args 传入的是table的场景
 * 
 * table：table在栈中的索引
 * args: 出参
 */
void
ngx_http_lua_process_args_option(ngx_http_request_t *r, lua_State *L,
    int table, ngx_str_t *args)
{
    u_char              *key;
    size_t               key_len;
    u_char              *value;
    size_t               value_len;
    size_t               len = 0;
    size_t               key_escape = 0;
    uintptr_t            total_escape = 0;
    int                  n;
    int                  i;
    u_char              *p;

    if (table < 0) {
        table = lua_gettop(L) + table + 1;
    }

    //1.先计算存放args字符串需要申请的内存空间
    n = 0;
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING) {
            luaL_error(L, "attempt to use a non-string key in the "
                       "\"args\" option table");
            return;
        }

        //key
        key = (u_char *) lua_tolstring(L, -2, &key_len);

        key_escape = 2 * ngx_http_lua_escape_uri(NULL, key, key_len,
                                                 NGX_ESCAPE_URI_COMPONENT);
        total_escape += key_escape;

        //value
        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            value = (u_char *) lua_tolstring(L, -1, &value_len);

            total_escape += 2 * ngx_http_lua_escape_uri(NULL, value, value_len,
                                                      NGX_ESCAPE_URI_COMPONENT);

            len += key_len + value_len + (sizeof("=") - 1);
            n++;

            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1)) {
                len += key_len;
                n++;
            }

            break;

        case LUA_TTABLE:

            //table
            i = 0;
            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {
                if (lua_isboolean(L, -1)) {
                    if (lua_toboolean(L, -1)) {
                        len += key_len;

                    } else {
                        lua_pop(L, 1);
                        continue;
                    }

                } else {
                    value = (u_char *) lua_tolstring(L, -1, &value_len);

                    if (value == NULL) {
                        luaL_error(L, "attempt to use %s as query arg value",
                                   luaL_typename(L, -1));
                        return;
                    }

                    total_escape +=
                        2 * ngx_http_lua_escape_uri(NULL, value,
                                                    value_len,
                                                    NGX_ESCAPE_URI_COMPONENT);

                    len += key_len + value_len + (sizeof("=") - 1);
                }

                if (i++ > 0) {
                    total_escape += key_escape;
                }

                n++;
                lua_pop(L, 1);
            }

            break;

        default:
            luaL_error(L, "attempt to use %s as query arg value",
                       luaL_typename(L, -1));
            return;
        }

        lua_pop(L, 1);
    }

    len += (size_t) total_escape;

    if (n > 1) {
        len += (n - 1) * (sizeof("&") - 1);
    }

    dd("len 1: %d", (int) len);

    if (r) {
        p = ngx_palloc(r->pool, len);
        if (p == NULL) {
            luaL_error(L, "no memory");
            return;
        }

    } else {
        p = lua_newuserdata(L, len);
    }

    //2.构建最终的args
    args->data = p;
    args->len = len;

    i = 0;
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        key = (u_char *) lua_tolstring(L, -2, &key_len);

        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:

            if (total_escape) {
                p = (u_char *) ngx_http_lua_escape_uri(p, key, key_len,
                                                       NGX_ESCAPE_URI_COMPONENT
                                                       );

            } else {
                dd("shortcut: no escape required");

                p = ngx_copy(p, key, key_len);
            }

            *p++ = '=';

            value = (u_char *) lua_tolstring(L, -1, &value_len);

            if (total_escape) {
                p = (u_char *) ngx_http_lua_escape_uri(p, value, value_len,
                                                       NGX_ESCAPE_URI_COMPONENT
                                                       );

            } else {
                p = ngx_copy(p, value, value_len);
            }

            if (i != n - 1) {
                /* not the last pair */
                *p++ = '&';
            }

            i++;

            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1)) {
                if (total_escape) {
                    p = (u_char *) ngx_http_lua_escape_uri(p, key, key_len,
                                                NGX_ESCAPE_URI_COMPONENT);

                } else {
                    dd("shortcut: no escape required");

                    p = ngx_copy(p, key, key_len);
                }

                if (i != n - 1) {
                    /* not the last pair */
                    *p++ = '&';
                }

                i++;
            }

            break;

        case LUA_TTABLE:

            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {

                if (lua_isboolean(L, -1)) {
                    if (lua_toboolean(L, -1)) {
                        if (total_escape) {
                            p = (u_char *)
                                    ngx_http_lua_escape_uri(p, key, key_len,
                                                      NGX_ESCAPE_URI_COMPONENT);

                        } else {
                            dd("shortcut: no escape required");

                            p = ngx_copy(p, key, key_len);
                        }

                    } else {
                        lua_pop(L, 1);
                        continue;
                    }

                } else {

                    if (total_escape) {
                        p = (u_char *)
                                ngx_http_lua_escape_uri(p, key,
                                                        key_len,
                                                        NGX_ESCAPE_URI_COMPONENT
                                                        );

                    } else {
                        dd("shortcut: no escape required");

                        p = ngx_copy(p, key, key_len);
                    }

                    *p++ = '=';

                    value = (u_char *) lua_tolstring(L, -1, &value_len);

                    if (total_escape) {
                        p = (u_char *)
                                ngx_http_lua_escape_uri(p, value,
                                                        value_len,
                                                        NGX_ESCAPE_URI_COMPONENT
                                                        );

                    } else {
                        p = ngx_copy(p, value, value_len);
                    }
                }

                if (i != n - 1) {
                    /* not the last pair */
                    *p++ = '&';
                }

                i++;
                lua_pop(L, 1);
            }

            break;

        default:
            luaL_error(L, "should not reach here");
            return;
        }

        lua_pop(L, 1);
    }

    if (p - args->data != (ssize_t) len) {
        luaL_error(L, "buffer error: %d != %d",
                   (int) (p - args->data), (int) len);
        return;
    }
}


/**
 * lua代码中执行了 ngx.redirect，导致lua代码yield
 * 
 * ngx.redirect("/foo", 301) 	-- 重定向，终止的当前请求的处理，即不再处理后续阶段
 */
static ngx_int_t
ngx_http_lua_handle_rewrite_jump(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread aborting request with URI rewrite jump: "
                   "\"%V?%V\"", &r->uri, &r->args);

    //如果coctx->cleanup不为null，则执行之
    ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    //设置协程状态为DEAD
    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 1 /* forcible */);
    ngx_http_lua_init_ctx(r, ctx);

    return NGX_OK;
}


/**
 * 打开name表示的文件，输出参数为of
 */
/* XXX ngx_open_and_stat_file is static in the core. sigh. */
ngx_int_t
ngx_http_lua_open_and_stat_file(u_char *name, ngx_open_file_info_t *of,
    ngx_log_t *log)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;

    if (of->fd != NGX_INVALID_FILE) {

        //stat系统调用获取文件的 ngx_file_info_t
        if (ngx_file_info(name, &fi) == NGX_FILE_ERROR) {
            of->failed = ngx_file_info_n;
            goto failed;
        }

        if (of->uniq == ngx_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (ngx_file_info(name, &fi) == NGX_FILE_ERROR) {
            of->failed = ngx_file_info_n;
            goto failed;
        }

        //是否是目录
        if (ngx_is_dir(&fi)) {
            goto done;
        }
    }

    //打开文件
    if (!of->log) {

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = ngx_open_file(name, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
                           NGX_FILE_OPEN, 0);

    } else {
        fd = ngx_open_file(name, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN,
                           NGX_FILE_DEFAULT_ACCESS);
    }

    if (fd == NGX_INVALID_FILE) {
        of->failed = ngx_open_file_n;
        goto failed;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", name);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }

        of->fd = NGX_INVALID_FILE;

        return NGX_ERROR;
    }

    if (ngx_is_dir(&fi)) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }

        of->fd = NGX_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->directio <= ngx_file_size(&fi)) {
            if (ngx_directio_on(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                              ngx_directio_on_n " \"%s\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = ngx_file_uniq(&fi);
    of->mtime = ngx_file_mtime(&fi);
    of->size = ngx_file_size(&fi);
    of->fs_size = ngx_file_fs_size(&fi);
    of->is_dir = ngx_is_dir(&fi);
    of->is_file = ngx_is_file(&fi);
    of->is_link = ngx_is_link(&fi);
    of->is_exec = ngx_is_exec(&fi);

    return NGX_OK;

failed:

    of->fd = NGX_INVALID_FILE;
    of->err = ngx_errno;

    return NGX_ERROR;
}


/**
 * 获取一个ngx_chain_t， 同时申请一个len大小的ngx_buf_t，挂载到ngx_chain_t上
 * 
 * 优先从free链表中获取可用的ngx_chain_t
 */
ngx_chain_t *
ngx_http_lua_chain_get_free_buf(ngx_log_t *log, ngx_pool_t *p,
    ngx_chain_t **free, size_t len)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    u_char       *start, *end;

    const ngx_buf_tag_t  tag = (ngx_buf_tag_t) &ngx_http_lua_module;

    //先尝试从free链表中获取
    if (*free) {
        //取出free链表第一个节点
        cl = *free;
        *free = cl->next;
        cl->next = NULL;

        b = cl->buf;
        start = b->start;
        end = b->end;
        //如果cl上的buf内存空间已经满足需求了
        if (start && (size_t) (end - start) >= len) {
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "lua reuse free buf memory %O >= %uz, cl:%p, p:%p",
                           (off_t) (end - start), len, cl, start);

            //重置ngx_buf_t
            ngx_memzero(b, sizeof(ngx_buf_t));

            b->start = start;
            b->pos = start;
            b->last = start;
            b->end = end;
            b->tag = tag;

            if (len) {
                b->temporary = 1;
            }

            return cl;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua reuse free buf chain, but reallocate memory "
                       "because %uz >= %O, cl:%p, p:%p", len,
                       (off_t) (b->end - b->start), cl, b->start);

        //释放ngx_buf_t内存
        if (ngx_buf_in_memory(b) && b->start) {
            ngx_pfree(p, b->start);
        }

        //清空ngx_buf_t结构体
        ngx_memzero(b, sizeof(ngx_buf_t));

        //如果申请的len为0，这里可以直接返回
        if (len == 0) {
            return cl;
        }

        //重新申请内存
        b->start = ngx_palloc(p, len);
        if (b->start == NULL) {
            return NULL;
        }

        //设置ngx_buf_t相关属性
        b->end = b->start + len;

        dd("buf start: %p", cl->buf->start);

        b->pos = b->start;
        b->last = b->start;
        b->tag = tag;
        b->temporary = 1;

        return cl;
    }

    /* 此处说明暂时没有空闲的ngx_chain_t结构体了， 需要创建新的 */

    //申请一个新的ngx_chain_t结构体
    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua allocate new chainlink and new buf of size %uz, cl:%p",
                   len, cl);

    //创建ngx_buf_t。如果len为0， 只创建一个ngx_buf_t，不申请空间
    cl->buf = len ? ngx_create_temp_buf(p, len) : ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    dd("buf start: %p", cl->buf->start);

    cl->buf->tag = tag;
    //ngx为NULL
    cl->next = NULL;

    return cl;
}


static int
ngx_http_lua_thread_traceback(lua_State *L, lua_State *co,
    ngx_http_lua_co_ctx_t *coctx)
{
    int         base;
    int         level, coid;
    lua_Debug   ar;

    base = lua_gettop(L);
    lua_checkstack(L, 3);
    lua_pushliteral(L, "stack traceback:");
    coid = 0;

    while (co) {

        if (coid >= NGX_HTTP_LUA_BT_MAX_COROS) {
            break;
        }

        lua_checkstack(L, 2);
        lua_pushfstring(L, "\ncoroutine %d:", coid++);

        level = 0;

        while (lua_getstack(co, level++, &ar)) {

            lua_checkstack(L, 5);

            if (level > NGX_HTTP_LUA_BT_DEPTH) {
                lua_pushliteral(L, "\n\t...");
                break;
            }

            lua_pushliteral(L, "\n\t");
            lua_getinfo(co, "Snl", &ar);
            lua_pushfstring(L, "%s:", ar.short_src);

            if (ar.currentline > 0) {
                lua_pushfstring(L, "%d:", ar.currentline);
            }

            if (*ar.namewhat != '\0') {  /* is there a name? */
                lua_pushfstring(L, " in function " LUA_QS, ar.name);

            } else {
                if (*ar.what == 'm') {  /* main? */
                    lua_pushliteral(L, " in main chunk");

                } else if (*ar.what == 'C' || *ar.what == 't') {
                    lua_pushliteral(L, " ?");  /* C function or tail call */

                } else {
                    lua_pushfstring(L, " in function <%s:%d>",
                                    ar.short_src, ar.linedefined);
                }
            }
        }

        if (lua_gettop(L) - base >= 15) {
            lua_concat(L, lua_gettop(L) - base);
        }

        /* check if the coroutine has a parent coroutine*/
        coctx = coctx->parent_co_ctx;
        if (!coctx || coctx->co_status == NGX_HTTP_LUA_CO_DEAD) {
            break;
        }

        co = coctx->co;
    }

    lua_concat(L, lua_gettop(L) - base);
    return 1;
}


/**
 * ngx_http_lua_do_call->.
 * 
 * pcall 异常处理函数
 */
int
ngx_http_lua_traceback(lua_State *L)
{
    if (!lua_isstring(L, 1)) { /* 'message' not a string? */
        return 1;  /* keep it intact */
    }

    //调用 Lua 的 debug.traceback,
    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }

    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }

    //然后把之前得到的错误信息压入栈中，将出错等级设置为 2 (也就是调用 ngx_http_lua_traceback 的函数，1 是调用 debug.traceback 的函数）
    lua_pushvalue(L, 1);  /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);  /* call debug.traceback */
    return 1;
}


/**
 * 注入ngx.arg api
 */
static void
ngx_http_lua_inject_arg_api(lua_State *L)
{
    //"arg"
    lua_pushliteral(L, "arg");
    //{} "arg"
    lua_newtable(L);    /*  .arg table aka {} */

    //{} {} "arg"
    lua_createtable(L, 0 /* narr */, 2 /* nrec */);    /*  the metatable */

    // func {} {} "arg"
    lua_pushcfunction(L, ngx_http_lua_param_set);
    //{"__newindex":func} {} "arg"
    lua_setfield(L, -2, "__newindex");

    //{__mt={xxx}} "arg"
    lua_setmetatable(L, -2);    /*  tie the metatable to param table */

    dd("top: %d, type -1: %s", lua_gettop(L), luaL_typename(L, -1));

    //ngx
    //ngx.arg={__mg={xxx}}
    lua_rawset(L, -3);    /*  set ngx.arg table */
}


/**
 * https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#ngxarg
 * 
 * ngx.arg 设值; ngx.arg.__new_index = ngx_http_lua_param_set
 */
static int
ngx_http_lua_param_set(lua_State *L)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_request_t          *r;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return 0;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "ctx not found");
    }

    //只能在body_filter阶段赋值
    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_BODY_FILTER);

    return ngx_http_lua_body_filter_param_set(L, r, ctx);
}


ngx_http_lua_co_ctx_t *
ngx_http_lua_get_co_ctx(lua_State *L, ngx_http_lua_ctx_t *ctx)
{
#ifdef HAVE_LUA_EXDATA2
    return (ngx_http_lua_co_ctx_t *) lua_getexdata2(L);
#else
    ngx_uint_t                   i;
    ngx_list_part_t             *part;
    ngx_http_lua_co_ctx_t       *coctx;

    // 如果是 请求的入口线程 则返回 ctx->entry_co_ctx
    if (L == ctx->entry_co_ctx.co) {
        return &ctx->entry_co_ctx;
    }

    if (ctx->user_co_ctx == NULL) {
        return NULL;
    }

    // 除了入口线程，还有一个工作线程 list 链表记录着这个请求说启动的所有线程上下文信息
    part = &ctx->user_co_ctx->part;
    coctx = part->elts;

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */

    // 当然这里做枚举了，作者在这里加了注释说有必要的话可以改成用 rbtree 提供 O(log(n))性能，对于轻度线程使用者来说，这不是问题
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            coctx = part->elts;
            i = 0;
        }

        // 找到了 L 的上下文信息结构体了，返回它
        if (coctx[i].co == L) {
            return &coctx[i];
        }
    }

    // 找不到返回 NULL
    return NULL;
#endif
}


ngx_http_lua_co_ctx_t *
ngx_http_lua_create_co_ctx(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx)
{
    ngx_http_lua_co_ctx_t       *coctx;

    // 在第一次，需要把线程 list 给创建起来
    if (ctx->user_co_ctx == NULL) {
        ctx->user_co_ctx = ngx_list_create(r->pool, 4,
                                           sizeof(ngx_http_lua_co_ctx_t));
        if (ctx->user_co_ctx == NULL) {
            return NULL;
        }
    }

    // 在线程 list 中添加一个上下文信息结构体
    coctx = ngx_list_push(ctx->user_co_ctx);
    if (coctx == NULL) {
        return NULL;
    }

    // 初始化结构体
    ngx_memzero(coctx, sizeof(ngx_http_lua_co_ctx_t));

    coctx->next_zombie_child_thread = &coctx->zombie_child_threads;
    coctx->co_ref = LUA_NOREF;

    // 作为返回值返回
    return coctx;
}


/**
 * http://qlee.in/openresty/2017/03/07/nginx-lua-coroutine-scheduler-6/
 * 
 * 这个函数主要是为了ngx.thread.spawn的处理，ngx.thread.spawn生成新的”light thread”，
 * 这个”light thread”运行优先级比它的父协程高，会优先运行，父协程被迫暂停。”light thread”运行结束或者yield后，
 * 再由ngx_http_lua_run_posted_threads去运行父协程。
 * 
 * 
 */
/* this is for callers other than the content handler */
ngx_int_t
ngx_http_lua_run_posted_threads(ngx_connection_t *c, lua_State *L,
    ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx, ngx_uint_t nreqs)
{
    ngx_int_t                        rc;
    ngx_http_lua_posted_thread_t    *pt;

    //从ctx->posted_threads指向的链表中依次取出每个元素，调用ngx_http_lua_run_thread运行
    for ( ;; ) {
        if (c->destroyed || c->requests != nreqs) {
            return NGX_DONE;
        }

        pt = ctx->posted_threads;
        if (pt == NULL) {
            return NGX_DONE;
        }

        ctx->posted_threads = pt->next;

        ngx_http_lua_probe_run_posted_thread(r, pt->co_ctx->co,
                                             (int) pt->co_ctx->co_status);

        if (pt->co_ctx->co_status != NGX_HTTP_LUA_CO_RUNNING) {
            continue;
        }

        ctx->cur_co_ctx = pt->co_ctx;

        rc = ngx_http_lua_run_thread(L, r, ctx, 0);

        if (rc == NGX_AGAIN) {
            continue;
        }

        if (rc == NGX_DONE) {
            ngx_http_lua_finalize_request(r, NGX_DONE);
            continue;
        }

        /* rc == NGX_ERROR || rc >= NGX_OK */

        //结束请求
        if (ctx->entered_content_phase) {
            ngx_http_lua_finalize_request(r, rc);
        }

        return rc;
    }

    /* impossible to reach here */
}


/**
 * 将父协程放在了ctx->posted_threads指向的链表中。
 * 
 * ngx_http_lua_run_posted_threads从ctx->posted_threads指向的链表中依次取出每个元素，调用ngx_http_lua_run_thread运行
 * 
 */
ngx_int_t
ngx_http_lua_post_thread(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx,
    ngx_http_lua_co_ctx_t *coctx)
{
    ngx_http_lua_posted_thread_t  **p;
    ngx_http_lua_posted_thread_t   *pt;

    pt = ngx_palloc(r->pool, sizeof(ngx_http_lua_posted_thread_t));
    if (pt == NULL) {
        return NGX_ERROR;
    }

    pt->co_ctx = coctx;
    pt->next = NULL;

    for (p = &ctx->posted_threads; *p; p = &(*p)->next) { /* void */ }

    *p = pt;

    return NGX_OK;
}


static void
ngx_http_lua_finalize_threads(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, lua_State *L)
{
    int                              ref;
    ngx_uint_t                       i;
    ngx_list_part_t                 *part;
    ngx_http_lua_co_ctx_t           *cc, *coctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua finalize threads");

#if 1
    coctx = ctx->on_abort_co_ctx;
    if (coctx && coctx->co_ref != LUA_NOREF) {
        if (coctx->co_status != NGX_HTTP_LUA_CO_SUSPENDED) {
            /* the on_abort thread contributes to the coctx->uthreads
             * counter only when it actually starts running */
            ngx_http_lua_cleanup_pending_operation(coctx);
            ctx->uthreads--;
        }

        ngx_http_lua_del_thread(r, L, ctx, coctx);
        ctx->on_abort_co_ctx = NULL;
    }
#endif

    if (ctx->user_co_ctx) {
        part = &ctx->user_co_ctx->part;
        cc = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                cc = part->elts;
                i = 0;
            }

            coctx = &cc[i];

            ref = coctx->co_ref;

            if (ref != LUA_NOREF) {
                ngx_http_lua_cleanup_pending_operation(coctx);

                ngx_http_lua_del_thread(r, L, ctx, coctx);

                ctx->uthreads--;
            }
        }

        ctx->user_co_ctx = NULL;
    }

    ngx_http_lua_assert(ctx->uthreads == 0);

    coctx = &ctx->entry_co_ctx;

    ref = coctx->co_ref;
    if (ref != LUA_NOREF) {
        ngx_http_lua_cleanup_pending_operation(coctx);
        ngx_http_lua_del_thread(r, L, ctx, coctx);
    }
}


static ngx_int_t
ngx_http_lua_post_zombie_thread(ngx_http_request_t *r,
    ngx_http_lua_co_ctx_t *parent, ngx_http_lua_co_ctx_t *thread)
{
    ngx_http_lua_posted_thread_t   *pt;

    pt = ngx_palloc(r->pool, sizeof(ngx_http_lua_posted_thread_t));
    if (pt == NULL) {
        return NGX_ERROR;
    }

    pt->co_ctx = thread;
    pt->next = NULL;

    ngx_http_lua_assert(parent->next_zombie_child_thread != NULL);

    *parent->next_zombie_child_thread = pt;
    parent->next_zombie_child_thread = &pt->next;

    return NGX_OK;
}


static void
ngx_http_lua_cleanup_zombie_child_uthreads(ngx_http_request_t *r,
    lua_State *L, ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t *coctx)
{
    ngx_http_lua_posted_thread_t   *pt;

    for (pt = coctx->zombie_child_threads; pt; pt = pt->next) {
        if (pt->co_ctx->co_ref != LUA_NOREF) {
            ngx_http_lua_del_thread(r, L, ctx, pt->co_ctx);
            ctx->uthreads--;
        }
    }

    coctx->zombie_child_threads = NULL;
    coctx->next_zombie_child_thread = &coctx->zombie_child_threads;
}


ngx_int_t
ngx_http_lua_check_broken_connection(ngx_http_request_t *r, ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t    *c;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http lua check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        return NGX_OK;
    }
#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return NGX_OK;
        }

        ev->eof = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, err,
                   "http lua recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return NGX_OK;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        dd("event is active");

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

#if 1
        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
#endif
    }

    dd("HERE %d", (int) n);

    if (n > 0) {
        return NGX_OK;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            dd("HERE");
            return NGX_OK;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    return NGX_HTTP_CLIENT_CLOSED_REQUEST;
}


/**
 * 
 * 用于检测客户端是否已经关闭了连接的 read_event_handler
 * 
 *  if (llcf->check_client_abort) {
 *      r->read_event_handler = ngx_http_lua_rd_check_broken_connection;
 *  }
 *
 */
void
ngx_http_lua_rd_check_broken_connection(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_event_t                *rev;
    ngx_http_lua_ctx_t         *ctx;

    if (r->done) {
        return;
    }

    rc = ngx_http_lua_check_broken_connection(r, r->connection->read);

    if (rc == NGX_OK) {
        return;
    }

    /* rc == NGX_ERROR || rc > NGX_OK */

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->on_abort_co_ctx == NULL) {
        r->connection->error = 1;
        ngx_http_lua_request_cleanup(ctx, 0);
        ngx_http_lua_finalize_request(r, rc);
        return;
    }

    if (ctx->on_abort_co_ctx->co_status != NGX_HTTP_LUA_CO_SUSPENDED) {

        /* on_abort already run for the current request handler */

        rev = r->connection->read;

        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                ngx_http_lua_request_cleanup(ctx, 0);
                ngx_http_lua_finalize_request(r,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        return;
    }

    ctx->uthreads++;
    ctx->resume_handler = ngx_http_lua_on_abort_resume;
    ctx->on_abort_co_ctx->co_status = NGX_HTTP_LUA_CO_RUNNING;
    ctx->cur_co_ctx = ctx->on_abort_co_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua waking up the on_abort callback thread");

    if (ctx->entered_content_phase) {
        r->write_event_handler = ngx_http_lua_content_wev_handler;

    } else {
        r->write_event_handler = ngx_http_core_run_phases;
    }

    r->write_event_handler(r);
}


static ngx_int_t
ngx_http_lua_on_abort_resume(ngx_http_request_t *r)
{
    lua_State                   *vm;
    ngx_int_t                    rc;
    ngx_uint_t                   nreqs;
    ngx_connection_t            *c;
    ngx_http_lua_ctx_t          *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_http_lua_wev_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua resuming the on_abort callback thread");

#if 0
    ngx_http_lua_probe_info("tcp resume");
#endif

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = ngx_http_lua_run_thread(vm, r, ctx, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NGX_DONE) {
        ngx_http_lua_finalize_request(r, NGX_DONE);
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (ctx->entered_content_phase) {
        ngx_http_lua_finalize_request(r, rc);
        return NGX_DONE;
    }

    return rc;
}


/**
 * 检查expect请求头
 * expect: 100-continue
 */
ngx_int_t
ngx_http_lua_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    //如果expect头的值不是 100-continue
    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    //发送 HTTP/1.1 100 Continue
    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    //上一步将要发送的内存复制到发送缓冲区即可返回。
    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}


/**
 * 结束请求
 */
void
ngx_http_lua_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_lua_ctx_t              *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx && ctx->cur_co_ctx) {
        //执行 coctx->cleanup(coctx);
        ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);
    }

    //正常的客户端请求
    if (r->connection->fd != (ngx_socket_t) -1) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    //结束 fake_request
    ngx_http_lua_finalize_fake_request(r, rc);
}


/**
 * ngx_http_lua_finalize_request->.
 * 
 */
void
ngx_http_lua_finalize_fake_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
#if (NGX_HTTP_SSL)
    ngx_ssl_conn_t            *ssl_conn;
    ngx_http_lua_ssl_ctx_t    *cctx;
#endif

    c = r->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lua finalize fake request: %d, a:%d, c:%d",
                   rc, r == c->data, r->main->count);

    if (rc == NGX_DONE) {
        ngx_http_lua_close_fake_request(r);
        return;
    }

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {

#if (NGX_HTTP_SSL)

        if (r->connection->ssl) {
            ssl_conn = r->connection->ssl->connection;
            if (ssl_conn) {
                c = ngx_ssl_get_connection(ssl_conn);

                if (c && c->ssl) {
                    cctx = ngx_http_lua_ssl_get_ctx(c->ssl->connection);
                    if (cctx != NULL) {
                        cctx->exit_code = 0;
                    }
                }
            }
        }

#endif

        ngx_http_lua_close_fake_request(r);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    ngx_http_lua_close_fake_request(r);
}


/**
 * ngx_http_lua_finalize_fake_request->.
 * 
 */
static void
ngx_http_lua_close_fake_request(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lua fake request count:%d", r->count);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http lua fake request "
                      "count is zero");
    }

    r->count--;

    if (r->count) {
        return;
    }

    //释放请求
    ngx_http_lua_free_fake_request(r);
    //关闭连接
    ngx_http_lua_close_fake_connection(c);
}


/**
 * ngx_http_lua_close_fake_request->.
 * 
 * 主要是执行注册在request上的cleanup
 * 
 */
void
ngx_http_lua_free_fake_request(ngx_http_request_t *r)
{
    ngx_log_t                 *log;
    ngx_http_cleanup_t        *cln;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http lua close fake "
                   "request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "http lua fake request "
                      "already closed");
        return;
    }

    //执行注册在request上的cleanup
    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    r->request_line.len = 0;

    r->connection->destroyed = 1;
}


/**
 * 关闭fake connection
 * 
 * 1.移除读写事件超时监听
 * 2.销毁c->pool
 * 3.释放连接结构体回 ngx_cycle->free_connections
 */
void
ngx_http_lua_close_fake_connection(ngx_connection_t *c)
{
    ngx_pool_t          *pool;
    ngx_connection_t    *saved_c = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lua close fake http connection %p", c);

    c->destroyed = 1;

    pool = c->pool;

    //1.移除读写事件超时监听
 
    //如果设置了读超时监听
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    //如果设置了写超时监听
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    /* When destroying the pool, the registered clean callbacks will be
     * executed. If the ngx_connection_t is freed before these callbacks are
     * run, and a new ngx_connection_t is created within a clean callback,
     * it is possible for the freed ngx_connection_t to be reused again.
     * If this reused ngx_connection_t is destroyed again within the clean
     * callback logic, it may result in other clean callbacks holding a
     * ngx_connection_t that has already been destroyed.
     */
    //2.销毁c->pool
    if (pool) {
        ngx_destroy_pool(pool);
    }

    /* we temporarily use a valid fd (0) to make ngx_free_connection happy */

    c->fd = 0;

    if (ngx_cycle->files) {
        saved_c = ngx_cycle->files[0];
    }

    //3.释放连接结构体
    ngx_free_connection(c);

    c->fd = (ngx_socket_t) -1;

    if (ngx_cycle->files) {
        ngx_cycle->files[0] = saved_c;
    }
}


/**
 * 初始化 Lua 虚拟机，并注入相关api。 ngx_http_lua_init->.
 * 
 * new_vm： 为lmcf->lua 指针，作为出参
 * parent_vm：NULL
 * 
 */
ngx_int_t
ngx_http_lua_init_vm(lua_State **new_vm, lua_State *parent_vm,
    ngx_cycle_t *cycle, ngx_pool_t *pool, ngx_http_lua_main_conf_t *lmcf,
    ngx_log_t *log, ngx_pool_cleanup_t **pcln)
{
    int                              rc;
    lua_State                       *L;
    ngx_uint_t                       i;
    ngx_pool_cleanup_t              *cln;
    ngx_http_lua_preload_hook_t     *hook;
    ngx_http_lua_vm_state_t         *state;

    //在cf->pool上的添加一个清理函数 ngx_http_lua_cleanup_vm, 用于清理 Lua VM
    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    //创建一个lua虚拟机实例, 并且注入相关ngx.* api
    /* create new Lua VM instance */
    L = ngx_http_lua_new_state(parent_vm, cycle, lmcf, log);
    if (L == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "lua initialize the "
                   "global Lua VM %p", L);

    //用于关闭L lua_close(L); 同时释放 state
    /* register cleanup handler for Lua VM */
    cln->handler = ngx_http_lua_cleanup_vm;

    state = ngx_alloc(sizeof(ngx_http_lua_vm_state_t), log);
    if (state == NULL) {
        return NGX_ERROR;
    }

    state->vm = L;
    state->count = 1;

    cln->data = state;

    if (lmcf->vm_cleanup == NULL) {
        /* this assignment will happen only once,
         * and also only for the main Lua VM */
        lmcf->vm_cleanup = cln;
    }

    if (pcln) {
        *pcln = cln;
    }

#ifdef OPENRESTY_LUAJIT
    /* load FFI library first since cdata needs it */
    luaopen_ffi(L);
#endif

    // 第三方模块加载, 对已注册的 preload_hooks 第三方模块进行加载
    if (lmcf->preload_hooks) {

        /* register the 3rd-party module's preload hooks */

        lua_getglobal(L, "package");
        lua_getfield(L, -1, "preload");

        hook = lmcf->preload_hooks->elts;

        for (i = 0; i < lmcf->preload_hooks->nelts; i++) {

            ngx_http_lua_probe_register_preload_package(L,
                                                        hook[i].package);

            lua_pushcfunction(L, hook[i].loader);
            lua_setfield(L, -2, (char *) hook[i].package);
        }

        lua_pop(L, 2);
    }

    *new_vm = L;

    //执行 require "resty.core"
    lua_getglobal(L, "require");
    lua_pushstring(L, "resty.core");

    rc = lua_pcall(L, 1, 1, 0);
    if (rc != 0) {
        return NGX_DECLINED;
    }

#ifdef OPENRESTY_LUAJIT
    //注入全局写保护，使用全局变量时会得到告警提示
    ngx_http_lua_inject_global_write_guard(L, log);
#endif

    return NGX_OK;
}


/**
 * 添加在cf->pool上的清理函数, data为ngx_http_lua_vm_state_t类型
 * 
 * 主要是调用 lua_close(L); 
 * 同时释放 ngx_http_lua_vm_state_t
 * 
 */
void
ngx_http_lua_cleanup_vm(void *data)
{
    lua_State                       *L;
    ngx_http_lua_vm_state_t         *state = data;

#if (DDEBUG)
    if (state) {
        dd("cleanup VM: c:%d, s:%p", (int) state->count, state->vm);
    }
#endif

    if (state) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "lua decrementing the reference count for Lua VM: %i",
                       state->count);

        if (--state->count == 0) {
            L = state->vm;
            ngx_http_lua_cleanup_conn_pools(L);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "lua close the global Lua VM %p", L);
            lua_close(L);
            ngx_free(state);
        }
    }
}


/**
 * 获取一条连接，并初始化其相关字段.
 * 
 * c->fd = (ngx_socket_t) -1;
 */
ngx_connection_t *
ngx_http_lua_create_fake_connection(ngx_pool_t *pool)
{
    ngx_log_t               *log;
    ngx_connection_t        *c;
    ngx_connection_t        *saved_c = NULL;

    /* (we temporarily use a valid fd (0) to make ngx_get_connection happy) */
    if (ngx_cycle->files) {
        saved_c = ngx_cycle->files[0];
    }

    //1. 从ngx_cycle->free_connections链表中获取一个连接, 这里fd传入的是0
    c = ngx_get_connection(0, ngx_cycle->log);

    if (ngx_cycle->files) {
        ngx_cycle->files[0] = saved_c;
    }

    if (c == NULL) {
        return NULL;
    }

    c->fd = (ngx_socket_t) -1;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    //2.初始化c->pool
    if (pool) {
        c->pool = pool;

    } else {
        c->pool = ngx_create_pool(128, c->log);
        if (c->pool == NULL) {
            goto failed;
        }
    }

    //3.创建log
    log = ngx_pcalloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto failed;
    }

    c->log = log;
    c->log->connection = c->number;
    c->log->action = NULL;
    c->log->data = NULL;

    c->log_error = NGX_ERROR_INFO;

#if 0
    c->buffer = ngx_create_temp_buf(c->pool, 2);
    if (c->buffer == NULL) {
        goto failed;
    }

    c->buffer->start[0] = CR;
    c->buffer->start[1] = LF;
#endif

    c->error = 1;

    dd("created fake connection: %p", c);

    return c;

failed:

    ngx_http_lua_close_fake_connection(c);
    return NULL;
}


/**
 * 创建一个 ngx_http_request_t 结构体， 并初始化相关字段
 */
ngx_http_request_t *
ngx_http_lua_create_fake_request(ngx_connection_t *c)
{
    ngx_http_request_t      *r;

    //创建一个ngx_http_request_t
    r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    r->pool = c->pool;

    dd("r pool allocated: %d", (int) (sizeof(ngx_http_lua_ctx_t)
       + sizeof(void *) * ngx_http_max_module + sizeof(ngx_http_cleanup_t)));

#if 0
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        goto failed;
    }

    r->header_in = c->buffer;
    r->header_end = c->buffer->start;

    if (ngx_list_init(&r->headers_out.headers, r->pool, 0,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 0,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }
#endif

    //创建每个模块的上下文结构体数组
    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        return NULL;
    }

#if 0
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                               * sizeof(ngx_http_variable_value_t));
    if (r->variables == NULL) {
        goto failed;
    }
#endif

    r->connection = c;

    r->headers_in.content_length_n = 0;
    c->data = r;
#if 0
    hc->request = r;
    r->http_connection = hc;
#endif
    r->signature = NGX_HTTP_MODULE;
    r->main = r;
    r->count = 1;

    r->method = NGX_HTTP_UNKNOWN;

    r->headers_in.keep_alive_n = -1;
    r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;
    r->discard_body = 1;

    dd("created fake request %p", r);

    return r;
}


/**
 * init_by_lua/init_worker_by_lua/exit_worker_by_lua 执行完lua代码后会调用此方法
 * 
 * status非0时进行一些日志记录，然后强制进行一次垃圾回收
 */
ngx_int_t
ngx_http_lua_report(ngx_log_t *log, lua_State *L, int status,
    const char *prefix)
{
    const char      *msg;

    if (status && !lua_isnil(L, -1)) {
        msg = lua_tostring(L, -1);
        if (msg == NULL) {
            msg = "unknown error";
        }

        ngx_log_error(NGX_LOG_ERR, log, 0, "%s error: %s", prefix, msg);
        lua_pop(L, 1);
    }

    /* force a full garbage-collection cycle */
    lua_gc(L, LUA_GCCOLLECT, 0);

    return status == 0 ? NGX_OK : NGX_ERROR;
}


/**
 * 执行栈顶的lua代码
 */
int
ngx_http_lua_do_call(ngx_log_t *log, lua_State *L)
{
    int                 status, base;
#if (NGX_PCRE)
    ngx_pool_t         *old_pool;
#endif

    base = lua_gettop(L);  /* function index */
    //把 ngx_http_lua_traceback 压入到 Lua 的虚拟栈，作为异常处理函数
    lua_pushcfunction(L, ngx_http_lua_traceback);  /* push traceback function */
    lua_insert(L, base);  /* put it under chunk and args */

#if (NGX_PCRE)
    old_pool = ngx_http_lua_pcre_malloc_init(ngx_cycle->pool);
#endif

    //然后调用了 lua_pcall 来执行刚才加载的 chunk，得到运行之后的状态，
    //如果出错则会得到一个描述错误的字符串（在栈底），status 为 0 表示运行成功，否则返回对应的错误码
    status = lua_pcall(L, 0, 0, base);

#if (NGX_PCRE)
    ngx_http_lua_pcre_malloc_done(old_pool);
#endif

    //调用 lua_remove 从栈中删除 ngx_http_lua_traceback 函数。
    lua_remove(L, base);

    //返回状态码
    return status;
}


static int
ngx_http_lua_get_raw_phase_context(lua_State *L)
{
    ngx_http_request_t      *r;
    ngx_http_lua_ctx_t      *ctx;

#ifdef OPENRESTY_LUAJIT
    r = lua_getexdata(L);
#else
    r = lua_touserdata(L, 1);
#endif

    if (r == NULL) {
        return 0;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return 0;
    }

    lua_pushinteger(L, (int) ctx->context);
    return 1;
}


/**
 * 在请求r上注册一个请求结束时的cleanup回调函数
 */
ngx_http_cleanup_t *
ngx_http_lua_cleanup_add(ngx_http_request_t *r, size_t size)
{
    ngx_http_cleanup_t  *cln;
    ngx_http_lua_ctx_t  *ctx;

    if (size == 0) {
        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

        r = r->main;

        //先尝试复用ctx->free_cleanup中的元素，而不是创建一个ngx_http_cleanup_t结构体
        if (ctx != NULL && ctx->free_cleanup) {
            //取出ctx->free_cleanup的首个元素
            cln = ctx->free_cleanup;
            ctx->free_cleanup = cln->next;

            dd("reuse cleanup: %p", cln);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua http cleanup reuse: %p", cln);

            //将cln插入r->cleanup队首
            cln->handler = NULL;
            cln->next = r->cleanup;

            //更新r->cleamup队首
            r->cleanup = cln;

            return cln;
        }
    }

    //创建一个新的ngx_http_cleanup_t，添加到r->cleanup队首
    return ngx_http_cleanup_add(r, size);
}


void
ngx_http_lua_cleanup_free(ngx_http_request_t *r, ngx_http_cleanup_pt *cleanup)
{
    ngx_http_cleanup_t  **last;
    ngx_http_cleanup_t   *cln;
    ngx_http_lua_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    r = r->main;

    cln = (ngx_http_cleanup_t *)
              ((u_char *) cleanup - offsetof(ngx_http_cleanup_t, handler));

    dd("cln: %p, cln->handler: %p, &cln->handler: %p",
       cln, cln->handler, &cln->handler);

    last = &r->cleanup;

    while (*last) {
        if (*last == cln) {
            *last = cln->next;

            cln->next = ctx->free_cleanup;
            ctx->free_cleanup = cln;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua http cleanup free: %p", cln);

            return;
        }

        last = &(*last)->next;
    }
}


#if (NGX_HTTP_LUA_HAVE_SA_RESTART)
void
ngx_http_lua_set_sa_restart(ngx_log_t *log)
{
    int                    *signo;
    int                     sigs[] = NGX_HTTP_LUA_SA_RESTART_SIGS;
    struct sigaction        act;

    for (signo = sigs; *signo != 0; signo++) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "setting SA_RESTART for signal %d", *signo);

        if (sigaction(*signo, NULL, &act) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno, "failed to get "
                          "sigaction for signal %d", *signo);
        }

        act.sa_flags |= SA_RESTART;

        if (sigaction(*signo, &act, NULL) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno, "failed to set "
                          "sigaction for signal %d", *signo);
        }
    }
}
#endif


/**
 * 不安全字符转义
 * 如果dst为NULL， 只是返回转义后的字符长度
 */
size_t
ngx_http_lua_escape_log(u_char *dst, u_char *src, size_t size)
{
    size_t          n;
    u_char          c;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

    if (dst == NULL) {

        /* find the number of characters to be escaped */

        n = 0;

        while (size) {
            c = *src;
            if (escape[c >> 5] & (1 << (c & 0x1f))) {
                n += 4;

            } else {
                n++;
            }

            src++;
            size--;
        }

        return n;
    }

    while (size) {
        c = *src;
        if (escape[c >> 5] & (1 << (c & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }

        size--;
    }

    return 0;
}


/**
 * 对dst指向的值进行uri编码
 * 如果值所有字符都不需要转义，则什么也不做
 * 如果有字符需要转义，则申请新的空间，将原值转义后复制到新申请的空间中。dst指向新值
 */
ngx_int_t
ngx_http_lua_copy_escaped_header(ngx_http_request_t *r,
    ngx_str_t *dst, int is_name)
{
    size_t       escape;
    size_t       len;
    u_char      *data;
    int          type;

    type = is_name
        ? NGX_HTTP_LUA_ESCAPE_HEADER_NAME : NGX_HTTP_LUA_ESCAPE_HEADER_VALUE;

    data = dst->data;
    len = dst->len;

    //这里只是计算需要转义的字符个数
    escape = ngx_http_lua_escape_uri(NULL, data, len, type);
    if (escape > 0) {
        /*
         * we allocate space for the trailing '\0' char here because nginx
         * header values must be null-terminated
         */
        //为dst申请空间
        dst->data = ngx_palloc(r->pool, len + 2 * escape + 1);
        if (dst->data == NULL) {
            return NGX_ERROR;
        }

        //进行uri编码
        ngx_http_lua_escape_uri(dst->data, data, len, type);
        dst->len = len + 2 * escape;
        dst->data[dst->len] = '\0';
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_lua_decode_base64mime(ngx_str_t *dst, ngx_str_t *src)
{
    size_t          i;
    u_char         *d, *s, ch;
    size_t          data_len = 0;
    u_char          buf[4];
    size_t          buf_len = 0;
    static u_char   basis[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    for (i = 0; i < src->len; i++) {
        ch = src->data[i];
        if (ch == '=') {
            break;
        }

        if (basis[ch] == 77) {
            continue;
        }

        data_len++;
    }

    if (data_len % 4 == 1) {
        return NGX_ERROR;
    }

    s = src->data;
    d = dst->data;

    for (i = 0; i < src->len; i++) {
        if (s[i] == '=') {
            break;
        }

        if (basis[s[i]] == 77) {
            continue;
        }

        buf[buf_len++] = s[i];
        if (buf_len == 4) {
            *d++ = (u_char) (basis[buf[0]] << 2 | basis[buf[1]] >> 4);
            *d++ = (u_char) (basis[buf[1]] << 4 | basis[buf[2]] >> 2);
            *d++ = (u_char) (basis[buf[2]] << 6 | basis[buf[3]]);
            buf_len = 0;
        }
    }

    if (buf_len > 1) {
        *d++ = (u_char) (basis[buf[0]] << 2 | basis[buf[1]] >> 4);
    }

    if (buf_len > 2) {
        *d++ = (u_char) (basis[buf[1]] << 4 | basis[buf[2]] >> 2);
    }

    dst->len = d - dst->data;

    return NGX_OK;
}


ngx_addr_t *
ngx_http_lua_parse_addr(lua_State *L, u_char *text, size_t len)
{
    ngx_addr_t           *addr;
    size_t                socklen;
    in_addr_t             inaddr;
    ngx_uint_t            family;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct in6_addr       inaddr6;
    struct sockaddr_in6  *sin6;

    /*
     * prevent MSVC8 warning:
     *    potentially uninitialized local variable 'inaddr6' used
     */
    ngx_memzero(&inaddr6, sizeof(struct in6_addr));
#endif

    inaddr = ngx_inet_addr(text, len);

    if (inaddr != INADDR_NONE) {
        family = AF_INET;
        socklen = sizeof(struct sockaddr_in);

#if (NGX_HAVE_INET6)

    } else if (ngx_inet6_addr(text, len, inaddr6.s6_addr) == NGX_OK) {
        family = AF_INET6;
        socklen = sizeof(struct sockaddr_in6);
#endif

    } else {
        return NULL;
    }

    addr = lua_newuserdata(L, sizeof(ngx_addr_t) + socklen + len);
    if (addr == NULL) {
        luaL_error(L, "no memory");
        return NULL;
    }

    addr->sockaddr = (struct sockaddr *) ((u_char *) addr + sizeof(ngx_addr_t));

    ngx_memzero(addr->sockaddr, socklen);

    addr->sockaddr->sa_family = (u_char) family;
    addr->socklen = socklen;

    switch (family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;
        ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) addr->sockaddr;
        sin->sin_addr.s_addr = inaddr;
        break;
    }

    addr->name.data = (u_char *) addr->sockaddr + socklen;
    addr->name.len = len;
    ngx_memcpy(addr->name.data, text, len);

    return addr;
}


void
ngx_http_lua_ffi_bypass_if_checks(ngx_http_request_t *r)
{
    r->disable_not_modified = 1;
}


#if (NGX_HTTP_V3)
void
ngx_http_lua_resume_quic_ssl_handshake(ngx_connection_t *c)
{
    ngx_int_t        rc, sslerr;
    ngx_ssl_conn_t  *ssl_conn;

    if (c == NULL || c->ssl == NULL || c->ssl->connection == NULL) {
        return;
    }

    if (!c->udp || c->read == NULL
        || c->read->handler != ngx_quic_input_handler)
    {
        return;
    }

    ssl_conn = c->ssl->connection;

    /* Openresty ssl lua scripts are triggered by registering callbacks into
     * openssl. If a lua script calls a yield api during execution, openssl's
     * SSL_do_handshake will return a specific error code. The application
     * should not treat these codes as fatal. The lua script will resume on
     * yield-related events until it finishes. After completion,
     * SSL_do_handshake should be called again to advance openssl's state
     * machine.
     *
     * Note that nginx quic and openresty ssl lua scripts are independent. When
     * openresty ssl lua runs, the client is waiting for a server response, so
     * nginx quic does not affect the execution of the lua script. After the lua
     * script finishes, SSL_do_handshake is called again, and nginx quic's
     * registered callback continues the handshake.
     */
    rc = SSL_do_handshake(ssl_conn);
    sslerr = SSL_get_error(ssl_conn, rc);

    if (rc <= 0 && sslerr != SSL_ERROR_WANT_READ
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        && sslerr != SSL_ERROR_WANT_X509_LOOKUP
#endif
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
        && sslerr != SSL_ERROR_WANT_CLIENT_HELLO_CB
#endif
    ) {
        /* If a fatal error occurs or lua script exits with error during quic
         * handshake, the quic connection will be closed immediately.
         */
        ngx_quic_close_connection(c, NGX_ERROR);

    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "lua resuming quic ssl handshake: rc %d, err %d, will "
                       "continue driving handshake or next lua script phase",
                       rc, sslerr);
    }
}
#endif

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
