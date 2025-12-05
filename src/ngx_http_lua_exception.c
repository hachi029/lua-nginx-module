
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_util.h"


/*  longjmp mark for restoring nginx execution after Lua VM crashing */
jmp_buf ngx_http_lua_exception;

/**
 * Override default Lua panic handler, output VM crash reason to nginx error
 * log, and restore execution to the nearest jmp-mark.
 *
 * @param L Lua state pointer
 * @retval Long jump to the nearest jmp-mark, never returns.
 * @note nginx request pointer should be stored in Lua thread's globals table
 * in order to make logging working.
 * */
/**
 * 会把异常信息写入到错误日志中，级别是 error，然后恢复抛异常的协程运行前的运行环境，这是通过 setjmp 和 longjmp 来实现的。
 * 
 * 此函数作为新的错误处理函数，会覆盖默认的 Lua panic 程序, 它的作用是：
 * 
 * 输出 Lua VM 奔溃原因到 Nginx 错误日志中
 * 跳到 setjmp 处恢复执行
 *   疑问：所以 ngx_quit 生效了么？最终是恢复执行还是退出了呢？
 * 
 */
int
ngx_http_lua_atpanic(lua_State *L)
{
#ifdef NGX_LUA_ABORT_AT_PANIC
    abort();
#else
    u_char                  *s = NULL;
    size_t                   len = 0;

    if (lua_type(L, -1) == LUA_TSTRING) {
        s = (u_char *) lua_tolstring(L, -1, &len);
    }

    if (s == NULL) {
        s = (u_char *) "unknown reason";
        len = sizeof("unknown reason") - 1;
    }

    ngx_log_stderr(0, "lua atpanic: Lua VM crashed, reason: %*s", len, s);
    ngx_quit = 1;

    /*  restore nginx execution */
    NGX_LUA_EXCEPTION_THROW(1);

    /* impossible to reach here */
#endif
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
