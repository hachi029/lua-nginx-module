
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_coroutine.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_probe.h"


/*
 * Design:
 *
 * In order to support using ngx.* API in Lua coroutines, we have to create
 * new coroutine in the main coroutine instead of the calling coroutine
 */


static int ngx_http_lua_coroutine_create(lua_State *L);
static int ngx_http_lua_coroutine_wrap(lua_State *L);
static int ngx_http_lua_coroutine_resume(lua_State *L);
static int ngx_http_lua_coroutine_yield(lua_State *L);
static int ngx_http_lua_coroutine_status(lua_State *L);


static const ngx_str_t
    ngx_http_lua_co_status_names[] =
    {
        ngx_string("running"),
        ngx_string("suspended"),
        ngx_string("normal"),
        ngx_string("dead"),
        ngx_string("zombie")
    };



/**
 * 重写了原生的接口
 * 
 * syntax: co = coroutine.create(f)
 * 
 */
static int
ngx_http_lua_coroutine_create(lua_State *L)
{
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    return ngx_http_lua_coroutine_create_helper(L, r, ctx, NULL, NULL);
}


static int
ngx_http_lua_coroutine_wrap_runner(lua_State *L)
{
    /* retrieve closure and insert it at the bottom of
     * the stack for coroutine.resume() */
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);

    return ngx_http_lua_coroutine_resume(L);
}


/**
 * syntax: co = coroutine.wrap(f)
 * 
 */
static int
ngx_http_lua_coroutine_wrap(lua_State *L)
{
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx = NULL;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_http_lua_coroutine_create_helper(L, r, ctx, &coctx, NULL);

    coctx->is_wrap = 1;

    lua_pushcclosure(L, ngx_http_lua_coroutine_wrap_runner, 1);

    return 1;
}


/**
 * coroutine.create/ngx.thread.spawn() 都调的这个函数
 * 
 * 调用 lua_newthread 创建一个新的协程
 * 
 * 此函数返回后，L的栈顶是新协程，co的栈顶是入口函数。
 */
int
ngx_http_lua_coroutine_create_helper(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t **pcoctx, int *co_ref)
{
    lua_State                     *vm;  /* the Lua VM */
    lua_State                     *co;  /* new coroutine to be created */
    ngx_http_lua_co_ctx_t         *coctx; /* co ctx for the new coroutine */
    ngx_http_lua_main_conf_t      *lmcf;

     // 参数检查，参数1 必须是函数
    luaL_argcheck(L, lua_isfunction(L, 1) && !lua_iscfunction(L, 1), 1,
                  "Lua function expected");

    // 上下文检查，必须在 rewrite access content 或者 timer 上下文中才能使用该函数，否则退出。
    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    // 这是主线程 vm
    vm = ngx_http_lua_get_lua_vm(r, ctx);

    /* create new coroutine on root Lua state, so it always yields
     * to main Lua thread
     */
    // 在 vm 基础上创建新的线程 co，也就是一个新的栈 co
    if (co_ref == NULL) {
        co = lua_newthread(vm);

    } else {
        lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);
        *co_ref = ngx_http_lua_new_cached_thread(vm, &co, lmcf, 0);
    }

    ngx_http_lua_probe_user_coroutine_create(r, L, co);

    // 这里对线程上下文做一些状态信息收集
    coctx = ngx_http_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        // 找不到现有的，就新建一个上下文信息
        coctx = ngx_http_lua_create_co_ctx(r, ctx);
        if (coctx == NULL) {
            return luaL_error(L, "no memory");
        }

    } else {
        // 重置本线程的上下文信息，毕竟这是全新的线程啊
        ngx_memzero(coctx, sizeof(ngx_http_lua_co_ctx_t));
        coctx->next_zombie_child_thread = &coctx->zombie_child_threads;
        coctx->co_ref = LUA_NOREF;
    }

    coctx->co = co;
    coctx->co_status = NGX_HTTP_LUA_CO_SUSPENDED;

#ifdef OPENRESTY_LUAJIT
    ngx_http_lua_set_req(co, r);
    ngx_http_lua_attach_co_ctx_to_L(co, coctx);
#else
    /* make new coroutine share globals of the parent coroutine.
     * NOTE: globals don't have to be separated! */
    /* 拷贝父协程的全局表到栈上 */
    ngx_http_lua_get_globals_table(L);
    /* 将全局表移动到新创建的协程co的栈上 */
    lua_xmove(L, co, 1);
    /* 从新协程栈上写入其的全局表 */
    ngx_http_lua_set_globals_table(co);
#endif

    // 把 co 从主线程 vm 移动到工作线程 L 的栈上
    lua_xmove(vm, L, 1);    /* move coroutine from main thread to L */

    if (co_ref) {
        lua_pop(vm, 1);  /* pop coroutines */
    }

    // 把 存放在 工作线程 L 上的线程入口函数 复制到 co
    lua_pushvalue(L, 1);    /* copy entry function to top of L*/
    lua_xmove(L, co, 1);    /* move entry function from L to co */

    // 把 线程上下文信息作为输出参数输出到函数外
    if (pcoctx) {
        *pcoctx = coctx;
    }

#ifdef NGX_LUA_USE_ASSERT
    coctx->co_top = 1;
#endif

    return 1;    /* return new coroutine to Lua */
}


/**
 * syntax: ok, ... = coroutine.resume(co, ...)
 * 
 */
static int
ngx_http_lua_coroutine_resume(lua_State *L)
{
    lua_State                   *co;
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;
    ngx_http_lua_co_ctx_t       *p_coctx; /* parent co ctx */

    // 从栈顶(参数1)获得要执行的线程 co
    co = lua_tothread(L, 1);

    luaL_argcheck(L, co, 1, "coroutine expected");

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    // 上下文检查
    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    // 把当前线程的上下文设为父线程上下文
    p_coctx = ctx->cur_co_ctx;
    if (p_coctx == NULL) {
        return luaL_error(L, "no parent co ctx found");
    }

    // 设置要执行的线程的父线程上下文，下面代码与执行 resume 有关。
    coctx = ngx_http_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    //dtrace 钩子
    ngx_http_lua_probe_user_coroutine_resume(r, L, co);

    //检查进程状态，如果不是 NGX_HTTP_LUA_CO_SUSPENDED 则不能进行 resume，直接返回错误
    if (coctx->co_status != NGX_HTTP_LUA_CO_SUSPENDED) {
        dd("coroutine resume: %d", coctx->co_status);

        lua_pushboolean(L, 0);
        lua_pushfstring(L, "cannot resume %s coroutine",
                        ngx_http_lua_co_status_names[coctx->co_status].data);
        return 2;
    }

    //设置父协程 ctx 的状态 为NORMAL。
    p_coctx->co_status = NGX_HTTP_LUA_CO_NORMAL;

    //设置协程的父协程 ctx。
    coctx->parent_co_ctx = p_coctx;

    dd("set coroutine to running");
    //设置子协程的状态 为RUNNING。
    coctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

    //设置协程操作是用户进行 RESUME。
    ctx->co_op = NGX_HTTP_LUA_USER_CORO_RESUME;
    // 把要执行的线程设置为当前线程
    //设置 ctx 的 cur_co_ctx 为即将 resume 的 coctx，当前协程 yield 后，将执行此协程。
    ctx->cur_co_ctx = coctx;

    /* yield and pass args to main thread, and resume target coroutine from
     * there */
    //yeild 回主线程，然后让主线程来 resume。
    //把当前线程放弃掉，然后回归到更上一层的线程，让它执行 resume 命令。
    /* lua_gettop(L) - 1表示留在栈中的返回值个数，
    * 由主线程取用之后，在lua_resume新协程时传递 */
    /* 减一个，表示不传底下的co */
    return lua_yield(L, lua_gettop(L) - 1);
}


/**
 * syntax: ... = coroutine.yield(...)
 */
static int
ngx_http_lua_coroutine_yield(lua_State *L)
{
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    // 上下文检查，在 rewrite access content timer 中允许运行，否则退出
    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = ctx->cur_co_ctx;

    coctx->co_status = NGX_HTTP_LUA_CO_SUSPENDED;

    ctx->co_op = NGX_HTTP_LUA_USER_CORO_YIELD;

    if (!coctx->is_uthread && coctx->parent_co_ctx) {
        // 如果有父线程，把父线程状态修改成正在运行
        dd("set coroutine to running");
        coctx->parent_co_ctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

        ngx_http_lua_probe_user_coroutine_yield(r, coctx->parent_co_ctx->co, L);

    } else {
        ngx_http_lua_probe_user_coroutine_yield(r, NULL, L);
    }

    //暂停当前线程，如果有父线程会让父线程继续跑下去
    /* yield and pass retvals to main thread,
     * and resume parent coroutine there */
    return lua_yield(L, lua_gettop(L));
}


/**
 * 注入协程相关api
 * 
 * https://github.com/LomoX-Offical/openresty-source-code-analysis/blob/master/lua-nginx-module/coroutine.md
 * 
 * coroutine apis 的 create , yield , resume , status 这四个函数被重新定义了，在非 body 和 header filter 情况下，会使用新的实现
 * 
 */
void
ngx_http_lua_inject_coroutine_api(ngx_log_t *log, lua_State *L)
{
    int         rc;

    // 创建 新的 coroutine table
    /* new coroutine table */
    lua_createtable(L, 0 /* narr */, 16 /* nrec */);

    //获取旧的 coroutine table
    /* get old coroutine table */
    lua_getglobal(L, "coroutine");

    // 把旧的 running 设置到新的里边
    /* set running to the old one */
    lua_getfield(L, -1, "running");
    lua_setfield(L, -3, "running");

    lua_getfield(L, -1, "create");
    lua_setfield(L, -3, "_create");

    lua_getfield(L, -1, "wrap");
    lua_setfield(L, -3, "_wrap");

    lua_getfield(L, -1, "resume");
    lua_setfield(L, -3, "_resume");

    lua_getfield(L, -1, "yield");
    lua_setfield(L, -3, "_yield");

    lua_getfield(L, -1, "status");
    lua_setfield(L, -3, "_status");

    /* pop the old coroutine */
    lua_pop(L, 1);

    // 设置 __create 函数
    lua_pushcfunction(L, ngx_http_lua_coroutine_create);
    lua_setfield(L, -2, "__create");

     // 设置 __wrap 函数
    lua_pushcfunction(L, ngx_http_lua_coroutine_wrap);
    lua_setfield(L, -2, "__wrap");

    lua_pushcfunction(L, ngx_http_lua_coroutine_resume);
    lua_setfield(L, -2, "__resume");

    lua_pushcfunction(L, ngx_http_lua_coroutine_yield);
    lua_setfield(L, -2, "__yield");

    lua_pushcfunction(L, ngx_http_lua_coroutine_status);
    lua_setfield(L, -2, "__status");

    // 把新的 table 设置为全局的 coroutine table，替代旧的 coroutine table
    lua_setglobal(L, "coroutine");

    /**
     * 1.第一段内容，在 coroutine table 添加 create ， yield ， resume ， status 四个成员函数。
     * 2.这四个成员函数均的实现都是先判断当前上下文 local ctx = raw_ctx(r)
     * 3.根据上下文是否是 header filter 或者 body filter 中，决定最终调用 _create 还是 __create 等，
     *  从上面ngx_http_lua_inject_coroutine_api 代码可以得知在这里 _* 函数就代表了 coroutine 原本的 apis ，而 __* 函数则代表了新加入的 coroutine apis 。
     *  从上面代码可以得知，在 header 和 body filter 上下文情况下，使用标准库 coroutine apis，而在其他上下文情况下，则使用 ngx lua module 新加入的 coroutine apis
     * 4.第二段内容，则是对 wrap 函数的重新定义，把 create 和 resume 的上述变化，都引入到 wrap 中，也就是根据不同上下文执行不同的 apis。
     * 5.最后一句 package.loaded.coroutine = coroutine 的意义在于，用刚定义的 coroutine 重新覆盖已加载的 coroutine 模块，使得 coroutine 不会被后面调用的 require 所覆盖。
     */
    /* inject coroutine APIs */
    {
        const char buf[] =
            "local keys = {'create', 'yield', 'resume', 'status', 'wrap'}\n"
#ifdef OPENRESTY_LUAJIT
            "local get_req = require 'thread.exdata'\n"
#else
            "local getfenv = getfenv\n"
#endif
            "for _, key in ipairs(keys) do\n"
               "local std = coroutine['_' .. key]\n"
               "local ours = coroutine['__' .. key]\n"
               "local raw_ctx = ngx._phase_ctx\n"
               "coroutine[key] = function (...)\n"
#ifdef OPENRESTY_LUAJIT
                    "local r = get_req()\n"
#else
                    "local r = getfenv(0).__ngx_req\n"
#endif
                    "if r ~= nil then\n"
#ifdef OPENRESTY_LUAJIT
                        "local ctx = raw_ctx()\n"
#else
                        "local ctx = raw_ctx(r)\n"
#endif
                        /* ignore header and body filters */
                        "if ctx ~= 0x020 and ctx ~= 0x040 then\n"
                            "return ours(...)\n"
                        "end\n"
                    "end\n"
                    "return std(...)\n"
                "end\n"
            "end\n"
            "package.loaded.coroutine = coroutine"
#if 0
            "debug.sethook(function () collectgarbage() end, 'rl', 1)"
#endif
            ;

        // 把 Lua 代码编入缓存
        rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=coroutine_api");
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to load Lua code for coroutine_api: %i: %s",
                      rc, lua_tostring(L, -1));

        lua_pop(L, 1);
        return;
    }

    // 执行上述的 Lua 代码，在不同的 上下文 中执行新旧两套不同的函数
    rc = lua_pcall(L, 0, 0, 0);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to run the Lua code for coroutine_api: %i: %s",
                      rc, lua_tostring(L, -1));
        lua_pop(L, 1);
    }
}


/**
 * syntax: status = coroutine.status(co)
 */
static int
ngx_http_lua_coroutine_status(lua_State *L)
{
    lua_State                     *co;  /* new coroutine to be created */
    ngx_http_request_t            *r;
    ngx_http_lua_ctx_t            *ctx;
    ngx_http_lua_co_ctx_t         *coctx; /* co ctx for the new coroutine */

    co = lua_tothread(L, 1);

    luaL_argcheck(L, co, 1, "coroutine expected");

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = ngx_http_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        lua_pushlstring(L, (const char *)
                        ngx_http_lua_co_status_names[NGX_HTTP_LUA_CO_DEAD].data,
                        ngx_http_lua_co_status_names[NGX_HTTP_LUA_CO_DEAD].len);
        return 1;
    }

    dd("co status: %d", coctx->co_status);

    lua_pushlstring(L, (const char *)
                    ngx_http_lua_co_status_names[coctx->co_status].data,
                    ngx_http_lua_co_status_names[coctx->co_status].len);
    return 1;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
