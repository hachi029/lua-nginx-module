
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_common.h"


/**
 * syntax: secs = ngx.now()
 */
double
ngx_http_lua_ffi_now(void)
{
    ngx_time_t              *tp;

    tp = ngx_timeofday();

    return tp->sec + tp->msec / 1000.0;
}


/**
 * ngx.req.start_time
 */
double
ngx_http_lua_ffi_req_start_time(ngx_http_request_t *r)
{
    return r->start_sec + r->start_msec / 1000.0;
}


/**
 * ngx.time
 * syntax: secs = ngx.time()
 * 
 * Returns the elapsed seconds from the epoch for the current time stamp from the nginx cached time 
 * (no syscall involved unlike Lua's date library).
 */
long
ngx_http_lua_ffi_time(void)
{
    return (long) ngx_time();
}


long
ngx_http_lua_ffi_monotonic_msec(void)
{
    return (long) ngx_current_msec;
}


/**
 * ngx.update_time
 * syntax: ngx.update_time()
 */
void
ngx_http_lua_ffi_update_time(void)
{
    ngx_time_update();
}


/**
 * ngx.today
 * syntax: str = ngx.today()
 * 
 * Returns current date (in the format yyyy-mm-dd) from the nginx cached time (no syscall involved unlike Lua's date library).
 */
void
ngx_http_lua_ffi_today(u_char *buf)
{
    ngx_tm_t                 tm;

    ngx_gmtime(ngx_time() + ngx_cached_time->gmtoff * 60, &tm);

    ngx_sprintf(buf, "%04d-%02d-%02d", tm.ngx_tm_year, tm.ngx_tm_mon,
                tm.ngx_tm_mday);
}


/**
 * syntax: str = ngx.localtime()
 * Returns the current time stamp (in the format yyyy-mm-dd hh:mm:ss) of the nginx cached time
 */
void
ngx_http_lua_ffi_localtime(u_char *buf)
{
    ngx_tm_t                 tm;

    ngx_gmtime(ngx_time() + ngx_cached_time->gmtoff * 60, &tm);

    ngx_sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", tm.ngx_tm_year,
                tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, tm.ngx_tm_min,
                tm.ngx_tm_sec);
}


/**
 * ngx.utctime
 * syntax: str = ngx.utctime()

 * Returns the current time stamp (in the format yyyy-mm-dd hh:mm:ss) of the nginx cached time
 * This is the UTC time.
 */
void
ngx_http_lua_ffi_utctime(u_char *buf)
{
    ngx_tm_t       tm;

    ngx_gmtime(ngx_time(), &tm);

    ngx_sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", tm.ngx_tm_year,
                tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, tm.ngx_tm_min,
                tm.ngx_tm_sec);
}


/**
 * ngx.cookie_time
 * syntax: str = ngx.cookie_time(sec)
 * 
 * Returns a formatted string can be used as the cookie expiration time.
 * The parameter sec is the time stamp in seconds (like those returned from ngx.time).
 * 
 * ngx.say(ngx.cookie_time(1290079655))
     -- yields "Thu, 18-Nov-10 11:27:35 GMT"

 */
int
ngx_http_lua_ffi_cookie_time(u_char *buf, long t)
{
    u_char                              *p;

    p = ngx_http_cookie_time(buf, t);
    return p - buf;
}


/**
 * ngx.http_time
 * syntax: str = ngx.http_time(sec)
 * Returns a formated string can be used as the http header time (for example, being used in Last-Modified header). 
 * The parameter sec is the time stamp in seconds (like those returned from ngx.time).
 * 
 *  ngx.say(ngx.http_time(1290079655))
     -- yields "Thu, 18 Nov 2010 11:27:35 GMT"
 * 
 */
void
ngx_http_lua_ffi_http_time(u_char *buf, long t)
{
    ngx_http_time(buf, t);
}


/**
 * ngx.parse_http_time
 * syntax: sec = ngx.parse_http_time(str)
 * Parse the http time string (as returned by ngx.http_time) into seconds. 
 * Returns the seconds or nil if the input string is in bad forms.
 * 
 *  local time = ngx.parse_http_time("Thu, 18 Nov 2010 11:27:35 GMT")
 *  if time == nil then
 *      ...
 *  end
 */
void
ngx_http_lua_ffi_parse_http_time(const u_char *str, size_t len,
    long *time)
{
    /* ngx_http_parse_time doesn't modify 'str' actually */
    *time = ngx_http_parse_time((u_char *) str, len);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
