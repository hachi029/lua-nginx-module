
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_uthread.h"
#include "ngx_http_lua_coroutine.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_probe.h"


#if 1
#undef ngx_http_lua_probe_info
#define ngx_http_lua_probe_info(msg)
#endif


static int ngx_http_lua_uthread_spawn(lua_State *L);
static int ngx_http_lua_uthread_wait(lua_State *L);
static int ngx_http_lua_uthread_kill(lua_State *L);


/**
 * 注入ngx.thread.*相关api
 */
void
ngx_http_lua_inject_uthread_api(ngx_log_t *log, lua_State *L)
{
    /* new thread table */
    lua_createtable(L, 0 /* narr */, 3 /* nrec */);

    lua_pushcfunction(L, ngx_http_lua_uthread_spawn);
    lua_setfield(L, -2, "spawn");

    lua_pushcfunction(L, ngx_http_lua_uthread_wait);
    lua_setfield(L, -2, "wait");

    lua_pushcfunction(L, ngx_http_lua_uthread_kill);
    lua_setfield(L, -2, "kill");

    lua_setfield(L, -2, "thread");
}


/**
 * syntax: co = ngx.thread.spawn(func, arg1, arg2, ...)
 * 
 * ngx.thread.spawn生成新的”light thread”，这个”light thread”运行优先级比它的父协程高，会优先运行，父协程被迫暂停。
 * ”light thread”运行结束或者yield后，再由ngx_http_lua_run_posted_threads去运行父协程
 * 
 */
static int
ngx_http_lua_uthread_spawn(lua_State *L)
{
    int                           n, co_ref;
    ngx_http_request_t           *r;
    ngx_http_lua_ctx_t           *ctx;
    ngx_http_lua_co_ctx_t        *coctx = NULL;

    n = lua_gettop(L);

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    //创建创建新协程，coroutine.create 也调用的这个函数。
    //此函数返回后，L的栈顶是新协程，co的栈顶是入口函数。
    ngx_http_lua_coroutine_create_helper(L, r, ctx, &coctx, &co_ref);

    /* anchor the newly created coroutine into the Lua registry */

    //如果入口函数有参数。
    if (n > 1) {
        //用 co 替换掉栈底元素，此时 L 的栈：co arg1 ... argn co。
        lua_replace(L, 1);
        //从 L 移动 n - 1 个元素到 coctx->co 栈中，此时 coctx->co 的栈：entry_func arg1 ... argn co。
        lua_xmove(L, coctx->co, n - 1);
    }

    coctx->co_ref = co_ref;
    coctx->is_uthread = 1;
    ctx->uthreads++;

    /* 设置状态 */
    coctx->co_status = NGX_HTTP_LUA_CO_RUNNING;
    ctx->co_op = NGX_HTTP_LUA_USER_THREAD_RESUME;

    ctx->cur_co_ctx->thread_spawn_yielded = 1;

    //将父协程放在了ctx->posted_threads指向的链表中。
    if (ngx_http_lua_post_thread(r, ctx, ctx->cur_co_ctx) != NGX_OK) {
        return luaL_error(L, "no memory");
    }

    /* 保存子线程的父协程上下文为当前协程 */
    coctx->parent_co_ctx = ctx->cur_co_ctx;
    //设置新创建的协程上下文成当前协程，下次调度时，会 resume 此协程。
    ctx->cur_co_ctx = coctx;

    //关联 coctx 和 co。
    ngx_http_lua_attach_co_ctx_to_L(coctx->co, coctx);

    ngx_http_lua_probe_user_thread_spawn(r, L, coctx->co);

    dd("yielding with arg %s, top=%d, index-1:%s", luaL_typename(L, -1),
       (int) lua_gettop(L), luaL_typename(L, 1));
    //让出当前协程的执行权限，以开始调度新的协程
    /* 将原协程的执行权切换出去，这里的参数1表示栈上留了一个值，这里是指新创建的协程
    * 主线程并不会取这个值，而是等到新线程spawn返回时作为返回值。
    * 此时L栈中是新协程，co栈中是参数和入口函数。
    */
    return lua_yield(L, 1);
}


/**
 * 
 * Waits on one or more child "light threads" 
 * 
 * returns the results of the first "light thread" that terminates (either successfully or with an error).
 * 
 * syntax: ok, res1, res2, ... = ngx.thread.wait(thread1, thread2, ...)
 * 
 * 默认是wait anyone of thread to finish, 还有wait_all model
 * 
 */
static int
ngx_http_lua_uthread_wait(lua_State *L)
{
    int                          i, nargs, nrets;
    lua_State                   *sub_co;
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx, *sub_coctx;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    //检查上下文是否是可以 yield 
    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = ctx->cur_co_ctx;

    //获取参数数量，参数是协程对象
    nargs = lua_gettop(L);
    if (nargs == 0) {
        return luaL_error(L, "at least one coroutine should be specified");
    }

    //逐个遍历检查要 wait 的协程
    for (i = 1; i <= nargs; i++) {
        //获取协程对象
        sub_co = lua_tothread(L, i);

        luaL_argcheck(L, sub_co, i, "lua thread expected");

        //协程上下文
        sub_coctx = ngx_http_lua_get_co_ctx(sub_co, ctx);
        if (sub_coctx == NULL) {
            return luaL_error(L, "no co ctx found");
        }

        if (!sub_coctx->is_uthread) {
            return luaL_error(L, "attempt to wait on a coroutine that is "
                              "not a user thread");
        }

        if (sub_coctx->parent_co_ctx != coctx) {
            return luaL_error(L, "only the parent coroutine can wait on the "
                              "thread");
        }

        //检查协程状态
        switch (sub_coctx->co_status) {
        /**
         * The status of the "light thread" coroutine can be "zombie" if
         *  1. the current "light thread" already terminates (either successfully or with an error),
         *  2. its parent coroutine is still alive, and
         *  3. its parent coroutine is not waiting on it with ngx.thread.wait.
         */
        case NGX_HTTP_LUA_CO_ZOMBIE:
            //是僵尸协程

            ngx_http_lua_probe_info("found zombie child");

            //获取返回值
            nrets = lua_gettop(sub_coctx->co);

            dd("child retval count: %d, %s: %s", (int) nrets,
               luaL_typename(sub_coctx->co, -1),
               lua_tostring(sub_coctx->co, -1));

            //设置成当前协程的返回值，作为 wait 方法的返回值
            if (nrets) {
                lua_xmove(sub_coctx->co, L, nrets);
            }

#if 1
            //从协程列表中删除协程
            ngx_http_lua_del_thread(r, L, ctx, sub_coctx);
            ctx->uthreads--;
#endif

            //返回
            return nrets;

        case NGX_HTTP_LUA_CO_DEAD:
            //已经是终止的协程了，已经被wait过了
            dd("uthread already waited: %p (parent %p)", sub_coctx,
               coctx);

            //如果还有其他协程需要检查，则继续
            if (i < nargs) {
                /* just ignore it if it is not the last one */
                continue;
            }

            //否则就返回错误
            /* being the last one */
            lua_pushnil(L);
            lua_pushliteral(L, "already waited or killed");
            return 2;

        default:
            //协程还活着，则继续等待
            dd("uthread %p still alive, status: %d, parent %p", sub_coctx,
               sub_coctx->co_status, coctx);
            break;
        }

        ngx_http_lua_probe_user_thread_wait(L, sub_coctx->co);
        sub_coctx->waited_by_parent = 1;
    }

    //让出执行权限，让子协程继续执行
    return lua_yield(L, 0);
}


/**
 * syntax: ok, err = ngx.thread.kill(thread)
 */
static int
ngx_http_lua_uthread_kill(lua_State *L)
{
    lua_State                   *sub_co;
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx, *sub_coctx;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = ctx->cur_co_ctx;

    //获取协程对象
    sub_co = lua_tothread(L, 1);
    luaL_argcheck(L, sub_co, 1, "lua thread expected");

    //获取协程的上下文
    sub_coctx = ngx_http_lua_get_co_ctx(sub_co, ctx);

    if (sub_coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    if (!sub_coctx->is_uthread) {
        lua_pushnil(L);
        lua_pushliteral(L, "not user thread");
        return 2;
    }

    //检查当前协程是否是要 kill 协程的父协程，不是不能 kill
    if (sub_coctx->parent_co_ctx != coctx) {
        lua_pushnil(L);
        lua_pushliteral(L, "killer not parent");
        return 2;
    }

    //检查协程是否还有未处理的请求
    if (sub_coctx->pending_subreqs > 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "pending subrequests");
        return 2;
    }

    //检查协程状态
    switch (sub_coctx->co_status) {
    case NGX_HTTP_LUA_CO_ZOMBIE:
        //删除协程并返回错误
        ngx_http_lua_del_thread(r, L, ctx, sub_coctx);
        ctx->uthreads--;

        lua_pushnil(L);
        lua_pushliteral(L, "already terminated");
        return 2;

    case NGX_HTTP_LUA_CO_DEAD:
        //直接返回错误
        lua_pushnil(L);
        lua_pushliteral(L, "already waited or killed");
        return 2;

    default:
        //协程仍在执行， 执行清理函数并删除协程
        ngx_http_lua_cleanup_pending_operation(sub_coctx);
        ngx_http_lua_del_thread(r, L, ctx, sub_coctx);
        ctx->uthreads--;

        //设置返回值
        lua_pushinteger(L, 1);
        return 1;
    }

    /* not reachable */
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
