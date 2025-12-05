
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_EXCEPTION_H_INCLUDED_
#define _NGX_HTTP_LUA_EXCEPTION_H_INCLUDED_


#include "ngx_http_lua_common.h"


#define NGX_LUA_EXCEPTION_TRY                                                \
    //setjmp 会保存当前程序的执行环境（包括寄存器状态、程序计数器等）到 jmp_buf 类型的变量 env 中，并返回 0
    if (setjmp(ngx_http_lua_exception) == 0)

#define NGX_LUA_EXCEPTION_CATCH                                              \
    else

#define NGX_LUA_EXCEPTION_THROW(x)                                           \
    //当后续通过 longjmp(env, val) 调用时，程序会跳回到 setjmp 调用的位置，并返回 val（而不是 0）
    longjmp(ngx_http_lua_exception, (x))


extern jmp_buf ngx_http_lua_exception;


int ngx_http_lua_atpanic(lua_State *L);


#endif /* _NGX_HTTP_LUA_EXCEPTION_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
