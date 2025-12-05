
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <nginx.h>
#include "ngx_http_lua_rewriteby.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_cache.h"


static ngx_int_t ngx_http_lua_rewrite_by_chunk(lua_State *L,
    ngx_http_request_t *r);


/**
 * ngx_http_lua_init->.
 * 
 * 如果配置了rewrite_by_lua指令， 安装一个REWRITE_PHASE的handler
 * */
ngx_int_t
ngx_http_lua_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_lua_loc_conf_t     *llcf;
    ngx_http_lua_ctx_t          *ctx;
    ngx_int_t                    rc;
    ngx_http_lua_main_conf_t    *lmcf;

    //URI 已经改变了，直接进行下一个模块
    /* XXX we need to take into account ngx_rewrite's location dump */
    if (r->uri_changed) {
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua rewrite handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    //获取模块配置
    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

    //这个变量用来标记 rewrite_by_lua 的回调方法是否被放置 rewrite 阶段最后（rewrite阶段所有handler的最后）
    if (!lmcf->postponed_to_rewrite_phase_end) {
        ngx_http_core_main_conf_t       *cmcf;
        ngx_http_phase_handler_t        tmp;
        ngx_http_phase_handler_t        *ph;
        ngx_http_phase_handler_t        *cur_ph;
        ngx_http_phase_handler_t        *last_ph;

        //只有第一个请求会执行到这里, 用于把当前的handler放到了 rewrite 阶段最后的位置
        lmcf->postponed_to_rewrite_phase_end = 1;

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        //将当前的handler移动到handlers数组的最后位置
        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[r->phase_handler];
        last_ph = &ph[cur_ph->next - 1];

#if 0
        if (cur_ph == last_ph) {
            dd("XXX our handler is already the last rewrite phase handler");
        }
#endif

        if (cur_ph < last_ph) {
            dd("swapping the contents of cur_ph and last_ph...");

            //tmp是当前的handler
            tmp      = *cur_ph;

            //dst, source
            memmove(cur_ph, cur_ph + 1,
                    (last_ph - cur_ph) * sizeof (ngx_http_phase_handler_t));

            //*last_ph赋值为当前的handler
            *last_ph = tmp;

            //重新调用当前位置的的phase_handler, 避免某个模块的回调被漏掉
            r->phase_handler--; /* redo the current ph */

            //该函数返回 NGX_DECLINED，代表希望 HTTP 框架按顺序执行下一个模块的回调
            return NGX_DECLINED;
        }
    }

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    //没有配置 rewrite_by_lua* 的 Lua 代码，跳到下一 handler
    if (llcf->rewrite_handler == NULL) {
        dd("no rewrite handler found");
        return NGX_DECLINED;
    }

    //获取模块上下文
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    dd("ctx = %p", ctx);

    //初始化模块上下文结构体 ngx_http_lua_ctx_t
    if (ctx == NULL) {
        ctx = ngx_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    dd("entered? %d", (int) ctx->entered_rewrite_phase);

    //entered_rewrite_phase 为1表示是第二次调用到此。第一次执行lua过程中暂停，被yield了
    if (ctx->entered_rewrite_phase) {
        dd("rewriteby: calling wev handler");
        //重新恢复其执行
        rc = ctx->resume_handler(r);
        dd("rewriteby: wev handler returns %d", (int) rc);

        if (rc == NGX_OK) {
            rc = NGX_DECLINED;
        }

        if (rc == NGX_DECLINED) {
            if (r->header_sent
                || (r->headers_out.status != 0 && ctx->out != NULL))
            {
                dd("header already sent");

                /* response header was already generated in rewrite_by_lua*,
                 * so it is no longer safe to proceed to later phases
                 * which may generate responses again */

                if (!ctx->eof) {
                    dd("eof not yet sent");

                    //发送一个有last_buf标志的ngx_buf_t
                    rc = ngx_http_lua_send_chain_link(r, ctx, NULL
                                                     /* indicate last_buf */);
                    if (rc == NGX_ERROR || rc > NGX_OK) {
                        return rc;
                    }
                }

                return NGX_HTTP_OK;
            }

            r->write_event_handler = ngx_http_core_run_phases;
            ctx->entered_rewrite_phase = 0;

            return NGX_DECLINED;
        }

        return rc;
    }

    //waiting_more_body 被设置时，直接结束 request 处理
    if (ctx->waiting_more_body) {
        return NGX_DONE;
    }

    //如果配置了需要读取请求体，但还没有读取
    if (llcf->force_read_body && !ctx->read_body_done) {
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        rc = ngx_http_read_client_request_body(r,
                                       ngx_http_lua_generic_phase_post_read);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        //标识一次没有读取完请求体，需要等可读事件到来后继续读取
        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            //返回 NGX_DONE，这个返回值会让 ngx_http_core_rewrite_phase  这个 checker 会让 HTTP 框架的控制权返回到事件模块，调度其他的请求
            //而这个请求则会在未来某个时刻被重新调度到，届时 rewrite_by_lua  的回调方法会被重入
            return NGX_DONE;
        }
    }

    dd("calling rewrite handler");
    //cmd->post方法，执行lua代码。 ngx_http_lua_rewrite_handler_inline/ngx_http_lua_rewrite_handler_file
    return llcf->rewrite_handler(r);
}


/**
 * rewrite_by_lua/rewrite_by_lua_block 的cmd->post, 指令解析时被挂载到 llcf->rewrite_handler
 * 
 * 用于执行lua代码
 */
ngx_int_t
ngx_http_lua_rewrite_handler_inline(ngx_http_request_t *r)
{
    lua_State                   *L;
    ngx_int_t                    rc;
    ngx_http_lua_loc_conf_t     *llcf;

    dd("rewrite by lua inline");

    //获取 location 配置
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
    //获取 Lua VM
    L = ngx_http_lua_get_lua_vm(r, NULL);

    //进行 rewrite 阶段的 Lua code 的“载入”（从缓存里取或者调用 lua_loadbuffer 载入）
    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->rewrite_src.value.data,
                                       llcf->rewrite_src.value.len,
                                       &llcf->rewrite_src_ref,
                                       llcf->rewrite_src_key,
                                       (const char *)
                                       llcf->rewrite_chunkname);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    //最后 Lua chunk 已经被拿到而且已经在栈顶

    return ngx_http_lua_rewrite_by_chunk(L, r);
}


/**
 * rewrite_by_lua_file 的cmd->post, 配置指令解析时被挂载到llcf->rewrite_handler
 */
ngx_int_t
ngx_http_lua_rewrite_handler_file(ngx_http_request_t *r)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    u_char                          *script_path;
    ngx_http_lua_loc_conf_t         *llcf;
    ngx_str_t                        eval_src;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    //计算文件路径的值
    if (ngx_http_complex_value(r, &llcf->rewrite_src, &eval_src) != NGX_OK) {
        return NGX_ERROR;
    }

    //获取文件全路径。
    script_path = ngx_http_lua_rebase_path(r->pool, eval_src.data,
                                           eval_src.len);

    if (script_path == NULL) {
        return NGX_ERROR;
    }

    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = ngx_http_lua_cache_loadfile(r->connection->log, L, script_path,
                                     &llcf->rewrite_src_ref,
                                     llcf->rewrite_src_key);
    if (rc != NGX_OK) {
        if (rc < NGX_HTTP_SPECIAL_RESPONSE) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return rc;
    }

    return ngx_http_lua_rewrite_by_chunk(L, r);
}


/**
 * ngx_http_lua_rewrite_handler_inline->.
 * 
 * 执行 Lua 代码, 调用此函数前，Lua chunk 已经被放置在栈顶
 * 
 */
static ngx_int_t
ngx_http_lua_rewrite_by_chunk(lua_State *L, ngx_http_request_t *r)
{
    int                      co_ref;
    lua_State               *co;
    ngx_int_t                rc;
    ngx_uint_t               nreqs;
    ngx_event_t             *rev;
    ngx_connection_t        *c;
    ngx_http_lua_ctx_t      *ctx;
    ngx_pool_cleanup_t      *cln;

    ngx_http_lua_loc_conf_t     *llcf;

    //生成一个协程 coroutine
    /*  {{{ new coroutine to handle request */
    co = ngx_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine to handle request");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

#ifndef OPENRESTY_LUAJIT
    /*  set closure's env table to new coroutine's globals table */
    ngx_http_lua_get_globals_table(co);
    //把新协程的 global 表成闭包的 env 表。
    //执行代码前，把 Lua 代码闭包的 env 表设置成了新协程的 global 表了，因此相当于在“沙箱”中执行 Lua 代码。
    lua_setfenv(co, -2);
#endif

    /*  save nginx request in coroutine globals table */
    ngx_http_lua_set_req(co, r);

    /*  {{{ initialize request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_lua_reset_ctx(r, L, ctx);

    //标记进入rewrite_phase
    ctx->entered_rewrite_phase = 1;

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    ngx_http_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /*  }}} */

    /*  {{{ register nginx pool cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }
    /*  }}} */

    ctx->context = NGX_HTTP_LUA_CONTEXT_REWRITE;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (llcf->check_client_abort) {
        r->read_event_handler = ngx_http_lua_rd_check_broken_connection;

#if (NGX_HTTP_V2)
        if (!r->stream) {
#endif

        rev = r->connection->read;

        if (!rev->active) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

#if (NGX_HTTP_V2)
        }
#endif

    } else {
        r->read_event_handler = ngx_http_block_reading;
    }

    c = r->connection;
    nreqs = c->requests;

    //执行lua chunk
    rc = ngx_http_lua_run_thread(L, r, ctx, 0);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    //chunk里的lua代码 yield 
    if (rc == NGX_AGAIN) {
        rc = ngx_http_lua_run_posted_threads(c, L, r, ctx, nreqs);

    //chunk里的lua代码执行完毕 
    } else if (rc == NGX_DONE) {
        ngx_http_lua_finalize_request(r, NGX_DONE);
        rc = ngx_http_lua_run_posted_threads(c, L, r, ctx, nreqs);
    }

    if (rc == NGX_OK || rc == NGX_DECLINED) {
        if (r->header_sent
            || (r->headers_out.status != 0 && ctx->out != NULL))
        {
            dd("header already sent");

            /* response header was already generated in rewrite_by_lua*,
             * so it is no longer safe to proceed to later phases
             * which may generate responses again */

            if (!ctx->eof) {
                dd("eof not yet sent");

                rc = ngx_http_lua_send_chain_link(r, ctx, NULL
                                                  /* indicate last_buf */);
                if (rc == NGX_ERROR || rc > NGX_OK) {
                    return rc;
                }
            }

            return NGX_HTTP_OK;
        }

        r->write_event_handler = ngx_http_core_run_phases;
        ctx->entered_rewrite_phase = 0;

        return NGX_DECLINED;
    }

    return rc;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
