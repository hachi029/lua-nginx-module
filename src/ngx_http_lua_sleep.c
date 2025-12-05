
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_util.h"
#include "ngx_http_lua_sleep.h"
#include "ngx_http_lua_contentby.h"


static int ngx_http_lua_ngx_sleep(lua_State *L);
static void ngx_http_lua_sleep_handler(ngx_event_t *ev);
static void ngx_http_lua_sleep_cleanup(void *data);
static ngx_int_t ngx_http_lua_sleep_resume(ngx_http_request_t *r);


/**
 * ngx.sleep
 * 
 * syntax: ngx.sleep(seconds)
 * 
 * 1.添加定时器，一段时间后执行回调函数
 * 2.调用lua_yield挂起协程
 * 3.在回调函数中调用lua_resume运行挂起的协程
 */
static int
ngx_http_lua_ngx_sleep(lua_State *L)
{
    int                          n;
    ngx_int_t                    delay; /* in msec */
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

    //参数个数, 只能为1
    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    //睡眠时间，单位 second
    delay = (ngx_int_t) (luaL_checknumber(L, 1) * 1000);

    if (delay < 0) {
        return luaL_error(L, "invalid sleep duration \"%d\"", delay);
    }

    //ngx_http_lua_module模块上下文结构体
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    //context: rewrite_by_lua*, access_by_lua*, content_by_lua*, ngx.timer.*, ssl_certificate_by_lua*, ssl_session_fetch_by_lua*, ssl_client_hello_by_lua*
    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE);

    //当前协程的上下文
    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    //执行 coctx->cleanup(coctx); 
    ngx_http_lua_cleanup_pending_operation(coctx);
    //设置新的cleanup
    coctx->cleanup = ngx_http_lua_sleep_cleanup;
    coctx->data = r;

    //设置定时器超时的handler
    coctx->sleep.handler = ngx_http_lua_sleep_handler;
    coctx->sleep.data = coctx;
    coctx->sleep.log = r->connection->log;

    if (delay == 0) {
        //如果delay为0，不会注册定时器事件
#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
        dd("posting 0 sec sleep event to head of delayed queue");

        coctx->sleep.delayed = 1;
        ngx_post_event(&coctx->sleep, &ngx_posted_delayed_events);
#else
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx.sleep(0)"
                      " called without delayed events patch, this will"
                      " hurt performance");
        ngx_add_timer(&coctx->sleep, (ngx_msec_t) delay);
#endif

    } else {
        dd("adding timer with delay %lu ms, r:%.*s", (unsigned long) delay,
           (int) r->uri.len, r->uri.data);

        ngx_add_timer(&coctx->sleep, (ngx_msec_t) delay);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua ready to sleep for %d ms", delay);

    //调用 lua_yield 挂起当前协程，会唤醒调用 lua_resume 的那个协程
    //而 lua_resume 则是在 ngx_http_lua_run_thread 里面被调用的（即回到 entry thread），之后 Nginx 即可调度其他的请求。 
    //等一轮网络调度（epoll 等）完成后，就轮到处理定时器事件了。而假如我们通过 ngx.sleep 产生的定时器事件到期，那么 ngx_http_lua_sleep_handler  这个回调就会被执行了
    return lua_yield(L, 0);
}


/**
 * ngx.sleep. 超时后的handler。
 * 
 * 目的就是恢复之前被挂起的协程。
 */
void
ngx_http_lua_sleep_handler(ngx_event_t *ev)
{
    ngx_connection_t        *c;
    ngx_http_request_t      *r;
    ngx_http_lua_ctx_t      *ctx;
    ngx_http_log_ctx_t      *log_ctx;
    ngx_http_lua_co_ctx_t   *coctx;

    //协程上下文
    coctx = ev->data;

    r = coctx->data;
    c = r->connection;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx == NULL) {
        return;
    }

    if (c->fd != (ngx_socket_t) -1) {  /* not a fake connection */
        log_ctx = c->log->data;
        log_ctx->current_request = r;
    }

    coctx->cleanup = NULL;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "lua sleep timer expired: \"%V?%V\"", &r->uri, &r->args);

    ctx->cur_co_ctx = coctx;

    //如果已经进入content阶段了
    if (ctx->entered_content_phase) {
        (void) ngx_http_lua_sleep_resume(r);

    } else {
        ctx->resume_handler = ngx_http_lua_sleep_resume;
        ngx_http_core_run_phases(r);
    }

    ngx_http_run_posted_requests(c);
}


/**
 * ngx api注入
 */
void
ngx_http_lua_inject_sleep_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_sleep);
    lua_setfield(L, -2, "sleep");
}


/**
 * ngx.sleep()时 设置在当前协程上下文上的cleanup函数
 * 
 * coctx->cleanup = ngx_http_lua_sleep_cleanup;
 */
static void
ngx_http_lua_sleep_cleanup(void *data)
{
    ngx_http_lua_co_ctx_t          *coctx = data;

    //从timer中移除
    if (coctx->sleep.timer_set) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "lua clean up the timer for pending ngx.sleep");

        ngx_del_timer(&coctx->sleep);
    }

#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
#if (nginx_version >= 1007005)
    if (coctx->sleep.posted) {
#else
    if (coctx->sleep.prev) {
#endif
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "lua clean up the posted event for pending ngx.sleep");

        /*
        * We need the extra parentheses around the argument
        * of ngx_delete_posted_event() just to work around macro issues in
        * nginx cores older than 1.7.5 (exclusive).
        */
        ngx_delete_posted_event((&coctx->sleep));
    }
#endif
}


/**
 * 超时事件的handler ngx_http_lua_sleep_handler->.
 * 
 * 恢复运行之前因为 ngx.sleep 而被挂起的协程
 */
static ngx_int_t
ngx_http_lua_sleep_resume(ngx_http_request_t *r)
{
    lua_State                   *vm;
    ngx_connection_t            *c;
    ngx_int_t                    rc;
    ngx_uint_t                   nreqs;
    ngx_http_lua_ctx_t          *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    //重置resume_handler
    ctx->resume_handler = ngx_http_lua_wev_handler;

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    //调用lua_resume
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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
