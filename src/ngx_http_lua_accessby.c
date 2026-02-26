
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <nginx.h>
#include "ngx_http_lua_accessby.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_cache.h"


static ngx_int_t ngx_http_lua_access_by_chunk(lua_State *L,
    ngx_http_request_t *r);


/**
 * ngx_http_lua_init->.
 * 
 *  如果配置了access_by_lua指令， 安装一个ACCESS_PHASE的handler
 * 
 *  返回：
 *   1.NGX_DECLINED：执行下一个handler
 *   2.NGX_AGAIN/NGX_DONE：未执行完，下次可写事件触发后，仍执行此handler
 *   3.NGX_OK: 根据satify指令，执行下一个阶段的handler，或执行当前阶段的下一个handler
 * 
 */
ngx_int_t
ngx_http_lua_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_lua_ctx_t         *ctx;
    ngx_http_lua_loc_conf_t    *llcf;
    ngx_http_lua_main_conf_t   *lmcf;
    ngx_http_phase_handler_t    tmp, *ph, *cur_ph, *last_ph;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua access handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

    //https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#access_by_lua_no_postpone
    //默认值为0，即将lua代码放到access阶段的所有handler最后执行
    // Controls whether or not to disable postponing access_by_lua* directives to run at the end of the access request-processing phase. 
    //By default, this directive is turned off and the Lua code is postponed to run at the end of the access phase
    if (!lmcf->postponed_to_access_phase_end) {

        //只在首个请求到来时进入这个逻辑
        lmcf->postponed_to_access_phase_end = 1;

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[r->phase_handler];

        /* we should skip the post_access phase handler here too */
        last_ph = &ph[cur_ph->next - 2];

        dd("ph cur: %d, ph next: %d", (int) r->phase_handler,
           (int) (cur_ph->next - 2));

#if 0
        if (cur_ph == last_ph) {
            dd("XXX our handler is already the last access phase handler");
        }
#endif

        if (cur_ph < last_ph) {
            dd("swapping the contents of cur_ph and last_ph...");

            tmp = *cur_ph;

            //将当前handler移动到handlers数组的最后位置
            memmove(cur_ph, cur_ph + 1,
                    (last_ph - cur_ph) * sizeof (ngx_http_phase_handler_t));

            *last_ph = tmp;

            r->phase_handler--; /* redo the current ph */

            //执行下一个handler
            return NGX_DECLINED;
        }
    }

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    //没有配置 access_by_lua_* 指令
    if (llcf->access_handler == NULL) {
        dd("no access handler found");
        return NGX_DECLINED;
    }

    //获取模块上下文结构体
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = ngx_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    dd("entered? %d", (int) ctx->entered_access_phase);


    //不是首次执行此handler
    if (ctx->entered_access_phase) {
        dd("calling wev handler");
        //在创建模块上下文结构体时，被初始化为 ngx_http_lua_wev_handler
        rc = ctx->resume_handler(r);
        dd("wev handler returns %d", (int) rc);

        if (rc == NGX_ERROR || rc == NGX_DONE || rc > NGX_OK) {
            return rc;
        }

        //
        if (rc == NGX_OK) {
            if (r->header_sent
                || (r->headers_out.status != 0 && ctx->out != NULL))
            {
                dd("header already sent");

                /* response header was already generated in access_by_lua*,
                 * so it is no longer safe to proceed to later phases
                 * which may generate responses again */

                if (!ctx->eof) {
                    dd("eof not yet sent");

                    //发送一个last_buf的特色chain
                    rc = ngx_http_lua_send_chain_link(r, ctx, NULL
                                                     /* indicate last_buf */);
                    if (rc == NGX_ERROR || rc > NGX_OK) {
                        return rc;
                    }
                }

                return NGX_HTTP_OK;
            }

            return NGX_OK;
        }

        //执行当前阶段的下一个handler
        return NGX_DECLINED;
    }
    /** 此处说明时首次执行此access_handler */

    if (ctx->waiting_more_body) {
        dd("WAITING MORE BODY");
        return NGX_DONE;
    }

    //如果配置了需要读取请求体
    if (llcf->force_read_body && !ctx->read_body_done) {
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        //读取请求体
        rc = ngx_http_read_client_request_body(r,
                                       ngx_http_lua_generic_phase_post_read);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        //当前阶段未执行完毕
        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    dd("calling access handler");
    //执行access阶段的Lua代码
    return llcf->access_handler(r);
}



/**
 * 
 * ngx_http_lua_access_handler->.
 * 
 * ngx_http_lua_access_by_lua/ngx_http_lua_access_by_block 配置指令的cmd->post
 * 
 * 执行access阶段配置的lua代码
 */
ngx_int_t
ngx_http_lua_access_handler_inline(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    lua_State                 *L;
    ngx_http_lua_loc_conf_t   *llcf;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    //获取主协程的lua_State结构体L
    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->access_src.value.data,
                                       llcf->access_src.value.len,
                                       &llcf->access_src_ref,
                                       llcf->access_src_key,
                                       (const char *) llcf->access_chunkname);

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    //执行lua代码
    return ngx_http_lua_access_by_chunk(L, r);
}


/**
 * ngx_http_lua_access_handler->.
 * 
 * ngx_http_lua_access_by_lua 配置指令的cmd->post
 * 
 * 执行access阶段配置的lua代码
 */
ngx_int_t
ngx_http_lua_access_handler_file(ngx_http_request_t *r)
{
    u_char                    *script_path;
    ngx_int_t                  rc;
    ngx_str_t                  eval_src;
    lua_State                 *L;
    ngx_http_lua_loc_conf_t   *llcf;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    /* Eval nginx variables in code path string first */
    if (ngx_http_complex_value(r, &llcf->access_src, &eval_src) != NGX_OK) {
        return NGX_ERROR;
    }

    //lua脚本获取文件全路径
    script_path = ngx_http_lua_rebase_path(r->pool, eval_src.data,
                                           eval_src.len);

    if (script_path == NULL) {
        return NGX_ERROR;
    }

    //获取lua_State
    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = ngx_http_lua_cache_loadfile(r->connection->log, L, script_path,
                                     &llcf->access_src_ref,
                                     llcf->access_src_key);
    if (rc != NGX_OK) {
        if (rc < NGX_HTTP_SPECIAL_RESPONSE) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_http_lua_assert(lua_isfunction(L, -1));

    return ngx_http_lua_access_by_chunk(L, r);
}


/**
 * 执行access阶段的lua代码
 */
static ngx_int_t
ngx_http_lua_access_by_chunk(lua_State *L, ngx_http_request_t *r)
{
    int                  co_ref;
    ngx_int_t            rc;
    ngx_uint_t           nreqs;
    lua_State           *co;
    ngx_event_t         *rev;
    ngx_connection_t    *c;
    ngx_http_lua_ctx_t  *ctx;
    ngx_pool_cleanup_t  *cln;

    ngx_http_lua_loc_conf_t     *llcf;

    /*  {{{ new coroutine to handle request */
    // 为这个请求创建新协程
    co = ngx_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine "
                      "to handle request");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 把要执行的 Lua 代码块从 Lua 虚拟机 L 出栈，并入栈到新的协程 Lua 虚拟机 co 上
    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

#ifndef OPENRESTY_LUAJIT
    /*  set closure's env table to new coroutine's globals table */
    //拿到co全局表，放到栈顶
    ngx_http_lua_get_globals_table(co);
    // 把栈顶的 全局表_G 设置为 Lua 代码块的_ENV
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

    // 清理 ctx 上下文结构体数据
    ngx_http_lua_reset_ctx(r, L, ctx);

    //设置entered_access_phase标识
    ctx->entered_access_phase = 1;

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    //lua_setexdata2(L, (void *) coctx);
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

    ctx->context = NGX_HTTP_LUA_CONTEXT_ACCESS;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    //如果需要检查客户端关闭连接
    if (llcf->check_client_abort) {
        r->read_event_handler = ngx_http_lua_rd_check_broken_connection;

#if (NGX_HTTP_V2)
        if (!r->stream) {
#endif

        rev = r->connection->read;

        if (!rev->active) {
            //添加读事件监听
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

#if (NGX_HTTP_V2)
        }
#endif

    } else {
        //设置可读事件的处理方法
        r->read_event_handler = ngx_http_block_reading;
    }

    c = r->connection;
    nreqs = c->requests;

    // 把 Lua 代码块放在新协程虚拟机上运行
    rc = ngx_http_lua_run_thread(L, r, ctx, 0);

    dd("returned %d", (int) rc);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        // Lua 代码让出了，等待下一次运行时机，接着跑这个 request 子协程
        rc = ngx_http_lua_run_posted_threads(c, L, r, ctx, nreqs);

        if (rc == NGX_ERROR || rc == NGX_DONE || rc > NGX_OK) {
            return rc;
        }

        if (rc != NGX_OK) {
            return NGX_DECLINED;
        }

    } else if (rc == NGX_DONE) {
        // Lua 代码要求结束请求，接着跑这个 request 子协程
        ngx_http_lua_finalize_request(r, NGX_DONE);

        rc = ngx_http_lua_run_posted_threads(c, L, r, ctx, nreqs);

        if (rc == NGX_ERROR || rc == NGX_DONE || rc > NGX_OK) {
            return rc;
        }

        if (rc != NGX_OK) {
            //执行当前阶段的下一个handler
            return NGX_DECLINED;
        }
    }

#if 1
    if (rc == NGX_OK) {
        // Lua 代码执行结束
        if (r->header_sent || (r->headers_out.status != 0 && ctx->out != NULL))
        {
            dd("header already sent");

            /* response header was already generated in access_by_lua*,
             * so it is no longer safe to proceed to later phases
             * which may generate responses again */

            if (!ctx->eof) {
                dd("eof not yet sent");

                // 判断条件，发送 body
                rc = ngx_http_lua_send_chain_link(r, ctx, NULL
                                                  /* indicate last_buf */);
                if (rc == NGX_ERROR || rc > NGX_OK) {
                    return rc;
                }
            }

            //结束请求
            return NGX_HTTP_OK;
        }

        // 根据satify指令，执行下一个阶段的handler，或执行当前阶段的下一个handler
        return NGX_OK;
    }
#endif

    // 让下一个 handler 处理
    return NGX_DECLINED;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
