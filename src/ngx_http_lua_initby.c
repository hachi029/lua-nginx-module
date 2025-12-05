
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ddebug.h"
#include "ngx_http_lua_initby.h"
#include "ngx_http_lua_util.h"


/**
 * ngx_http_lua_shared_memory_init
 *  \ lmcf->init_handler
 * 
 * init_by_lua/init_by_lua_block的cmd->post
 * 
 * 执行 init_by_lua_*阶段的lua代码
 */
ngx_int_t
ngx_http_lua_init_by_inline(ngx_log_t *log, ngx_http_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;
    const char *chunkname;


    if (lmcf->init_chunkname == NULL) {
        chunkname = "=init_by_lua";

    } else {
        chunkname = (const char *) lmcf->init_chunkname;
    }

    //加载一段 Lua 代码块，但不运行它。 如果没有错误， lua_load 把一个编译好的代码块作为一个 Lua 函数压到栈顶。 否则，压入错误消息。
    //把传入的 Lua 代码字符串解析成代码块，并作为一个函数压栈。
    status = luaL_loadbuffer(L, (char *) lmcf->init_src.data,
                             lmcf->init_src.len, chunkname)
             //如果luaL_loadbuffer没有错误，则执行
             || ngx_http_lua_do_call(log, L);

    //调用 ngx_http_lua_report 根据 status 状态码，把错误信息以 NGX_LOG_ERR 日志等级写入 error 日志，并进行资源回收。
    return ngx_http_lua_report(log, L, status, "init_by_lua");
}


/**
 * init_by_lua_file的cmd->post
 */
ngx_int_t
ngx_http_lua_init_by_file(ngx_log_t *log, ngx_http_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadfile(L, (char *) lmcf->init_src.data)
             || ngx_http_lua_do_call(log, L);

    return ngx_http_lua_report(log, L, status, "init_by_lua_file");
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
