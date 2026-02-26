
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_COMMON_H_INCLUDED_
#define _NGX_HTTP_LUA_COMMON_H_INCLUDED_


#include "ngx_http_lua_autoconf.h"

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include <setjmp.h>
#include <stdint.h>

#include <luajit.h>
#include <lualib.h>
#include <lauxlib.h>


#if defined(NDK) && NDK
#include <ndk.h>

typedef struct {
    size_t       size;
    int          ref;
    u_char      *key;
    u_char      *chunkname;
    ngx_str_t    script;
} ngx_http_lua_set_var_data_t;
#endif


#ifdef NGX_LUA_USE_ASSERT
#include <assert.h>
#   define ngx_http_lua_assert(a)  assert(a)
#else
#   define ngx_http_lua_assert(a)
#endif


/**
 * max positive +1.7976931348623158e+308
 * min positive +2.2250738585072014e-308
 */
#ifndef NGX_DOUBLE_LEN
#define NGX_DOUBLE_LEN  25
#endif


#if (NGX_PCRE)
#   if (NGX_PCRE2)
#       define LUA_HAVE_PCRE_JIT 1
#   else

#include <pcre.h>

#       if (PCRE_MAJOR > 8) || (PCRE_MAJOR == 8 && PCRE_MINOR >= 21)
#           define LUA_HAVE_PCRE_JIT 1
#       else
#           define LUA_HAVE_PCRE_JIT 0
#       endif
#   endif
#endif


#if (nginx_version < 1006000)
#   error at least nginx 1.6.0 is required but found an older version
#endif

#if LUA_VERSION_NUM != 501
#   error unsupported Lua language version
#endif

#if !defined(LUAJIT_VERSION_NUM) || (LUAJIT_VERSION_NUM < 20000)
#   error unsupported LuaJIT version
#endif


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)
#   define NGX_HTTP_LUA_USE_OCSP 1
#endif

#ifndef NGX_HTTP_PERMANENT_REDIRECT
#   define NGX_HTTP_PERMANENT_REDIRECT 308
#endif

#ifndef NGX_HAVE_SHA1
#   if (nginx_version >= 1011002)
#       define NGX_HAVE_SHA1 1
#   endif
#endif

#ifndef MD5_DIGEST_LENGTH
#   define MD5_DIGEST_LENGTH 16
#endif

#ifndef NGX_HTTP_LUA_MAX_ARGS
#   define NGX_HTTP_LUA_MAX_ARGS 100
#endif

//ngx.resp.get_headers/ngx.req.get_headers 获取的最大的header数量
#ifndef NGX_HTTP_LUA_MAX_HEADERS
#   define NGX_HTTP_LUA_MAX_HEADERS 100
#endif


/* Nginx HTTP Lua Inline tag prefix */

#define NGX_HTTP_LUA_INLINE_TAG "nhli_"

#define NGX_HTTP_LUA_INLINE_TAG_LEN                                          \
    (sizeof(NGX_HTTP_LUA_INLINE_TAG) - 1)

#define NGX_HTTP_LUA_INLINE_KEY_LEN                                          \
    (NGX_HTTP_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

/* Nginx HTTP Lua File tag prefix */

#define NGX_HTTP_LUA_FILE_TAG "nhlf_"

#define NGX_HTTP_LUA_FILE_TAG_LEN                                            \
    (sizeof(NGX_HTTP_LUA_FILE_TAG) - 1)

#define NGX_HTTP_LUA_FILE_KEY_LEN                                            \
    (NGX_HTTP_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)


/* must be within 16 bit */
#define NGX_HTTP_LUA_CONTEXT_SET                0x0001
#define NGX_HTTP_LUA_CONTEXT_REWRITE            0x0002
#define NGX_HTTP_LUA_CONTEXT_ACCESS             0x0004
#define NGX_HTTP_LUA_CONTEXT_CONTENT            0x0008
#define NGX_HTTP_LUA_CONTEXT_LOG                0x0010
#define NGX_HTTP_LUA_CONTEXT_HEADER_FILTER      0x0020
#define NGX_HTTP_LUA_CONTEXT_BODY_FILTER        0x0040
#define NGX_HTTP_LUA_CONTEXT_TIMER              0x0080
#define NGX_HTTP_LUA_CONTEXT_INIT_WORKER        0x0100
#define NGX_HTTP_LUA_CONTEXT_BALANCER           0x0200
#define NGX_HTTP_LUA_CONTEXT_SSL_CERT           0x0400
#define NGX_HTTP_LUA_CONTEXT_SSL_SESS_STORE     0x0800
#define NGX_HTTP_LUA_CONTEXT_SSL_SESS_FETCH     0x1000
#define NGX_HTTP_LUA_CONTEXT_EXIT_WORKER        0x2000
#define NGX_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO   0x4000
#define NGX_HTTP_LUA_CONTEXT_SERVER_REWRITE     0x8000


#define NGX_HTTP_LUA_FFI_NO_REQ_CTX         -100
#define NGX_HTTP_LUA_FFI_BAD_CONTEXT        -101


#if (NGX_PTR_SIZE >= 8 && !defined(_WIN64))
#   define ngx_http_lua_lightudata_mask(ludata)                              \
        ((void *) ((uintptr_t) (&ngx_http_lua_##ludata) & ((1UL << 47) - 1)))
#else
#   define ngx_http_lua_lightudata_mask(ludata)                              \
        (&ngx_http_lua_##ludata)
#endif


typedef struct ngx_http_lua_co_ctx_s  ngx_http_lua_co_ctx_t;

typedef struct ngx_http_lua_sema_mm_s  ngx_http_lua_sema_mm_t;

typedef struct ngx_http_lua_srv_conf_s  ngx_http_lua_srv_conf_t;

typedef struct ngx_http_lua_main_conf_s  ngx_http_lua_main_conf_t;

typedef struct ngx_http_lua_header_val_s  ngx_http_lua_header_val_t;

typedef struct ngx_http_lua_posted_thread_s  ngx_http_lua_posted_thread_t;

typedef struct ngx_http_lua_balancer_peer_data_s
    ngx_http_lua_balancer_peer_data_t;

typedef ngx_int_t (*ngx_http_lua_main_conf_handler_pt)(ngx_log_t *log,
    ngx_http_lua_main_conf_t *lmcf, lua_State *L);

typedef ngx_int_t (*ngx_http_lua_srv_conf_handler_pt)(ngx_http_request_t *r,
    ngx_http_lua_srv_conf_t *lscf, lua_State *L);

typedef ngx_int_t (*ngx_http_lua_set_header_pt)(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);


typedef struct {
    u_char              *package;
    lua_CFunction        loader;
} ngx_http_lua_preload_hook_t;


/**
 * https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#lua_thread_cache_max_entries
 * 
 * 
 * lmcf->free_lua_threads
 * lmcf->cached_lua_threads
 * 
 * 每个结构体标识一个缓存的 协程
 */
typedef struct {
    //ref为协程在存放所有协程的table中的索引
    int             ref;
    //协程
    lua_State      *co;
    //用于组成双向队列
    ngx_queue_t     queue;
} ngx_http_lua_thread_ref_t;


/**
 * ngx_http_lua_module 在main级别的配置结构体
 * */
struct ngx_http_lua_main_conf_s {
    //Postconfiguration阶段 ngx_http_lua_init()中创建的，注入了ngx.* api
    //如果关闭了code_cache，则每个请求都会重新创建，参考ngx_http_lua_create_ctx()方法
    lua_State           *lua;
    //lua_State 清理函数 ngx_http_lua_cleanup_vm， 用于关闭 lua_State
    ngx_pool_cleanup_t  *vm_cleanup;

    //配置指令lua_package_path的值
    ngx_str_t            lua_path;
    //配置指令lua_package_cpath的值， 设置Lua c模块搜索路径
    ngx_str_t            lua_cpath;

    ngx_cycle_t         *cycle;
    ngx_pool_t          *pool;

    //配置指令值 lua_max_pending_timers，处于pending状态timers最大数量
    ngx_int_t            max_pending_timers;
    //状态值，当前处于pending状态的timer
    ngx_int_t            pending_timers;

    //配置指令值 lua_max_running_timers，处于running状态timers最大数量
    ngx_int_t            max_running_timers;
    //状态值，当前处于running状态的timer
    ngx_int_t            running_timers;

    //用于监听进程退出时间，退出时将触发此connection上的read_event, 进而执行事件处理函数 ngx_http_lua_abort_pending_timers
    ngx_connection_t    *watcher;  /* for watching the process exit event */

    //配置指令值 lua_thread_cache_max_entries. 设置 lua thread object cache 的最大个数。默认值 1024
    ngx_int_t            lua_thread_cache_max_entries;

    //ngx_http_lua_set_handlers 数组组成的hash表，在ngx_http_lua_init_builtin_headers_out中初始化
    //key 为header的name, value为 ngx_http_lua_set_handlers 数组中对应元素的地址
    ngx_hash_t           builtin_headers_out;

#if (NGX_PCRE)
    ngx_int_t            regex_cache_entries;
    //lua_regex_cache_max_entries 配置指, 正则编译缓存最大个数。默认值 1024
    ngx_int_t            regex_cache_max_entries;
    //https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#lua_regex_match_limit
    ngx_int_t            regex_match_limit;
#endif

#if (LUA_HAVE_PCRE_JIT)
#if (NGX_PCRE2)
    pcre2_jit_stack     *jit_stack;
#else
    pcre_jit_stack      *jit_stack;
#endif
#endif

    //元素类型为ngx_shm_zone_t
    ngx_array_t         *shm_zones;  /* of ngx_shm_zone_t* */

    //存放lua_shared_dict配置指令配置的所有shared_dict, 元素类型 ngx_shm_zone_t
    ngx_array_t         *shdict_zones; /* shm zones of "shdict" */

    ngx_array_t         *preload_hooks; /* of ngx_http_lua_preload_hook_t */

    //配置指令值 rewrite_by_lua_no_postpone， 默认值0
    ngx_flag_t           postponed_to_rewrite_phase_end;
    //配置指令值 access_by_lua_no_postpone， 默认值0
    //是否将本模块的access_handler放至所有access_handler的最后
    ngx_flag_t           postponed_to_access_phase_end;

    // 为init_by_lua*的 cmd->post. ngx_http_lua_init_by_inline or ngx_http_lua_init_by_file 
    ngx_http_lua_main_conf_handler_pt    init_handler;
    //init_by_file: 文件全路径
    //init_by_lua: lua代码字符串
    ngx_str_t                            init_src;
    //init_by_lua: 生成的chunk名称
    u_char                              *init_chunkname;

    //init_worker阶段的cmd->post ngx_http_lua_init_worker_by_inline or ngx_http_lua_init_worker_by_file
    ngx_http_lua_main_conf_handler_pt    init_worker_handler;
    ngx_str_t                            init_worker_src;
    u_char                              *init_worker_chunkname;

    //exit_worker阶段的cmd->post
    ngx_http_lua_main_conf_handler_pt    exit_worker_handler;
    ngx_str_t                            exit_worker_src;
    u_char                              *exit_worker_chunkname;

    ngx_chain_t                            *body_filter_chain;
                    /* neither yielding nor recursion is possible in
                     * body_filter_by_lua*, so there cannot be any races among
                     * concurrent requests when storing the chain
                     * data pointer in the main conf.
                     */

    ngx_http_variable_value_t              *setby_args;
                    /* neither yielding nor recursion is possible in
                     * set_by_lua*, so there cannot be any races among
                     * concurrent requests when storing the args pointer
                     * in the main conf.
                     */

    size_t                                  setby_nargs;
                    /* neither yielding nor recursion is possible in
                     * set_by_lua*, so there cannot be any races among
                     * concurrent requests when storing the nargs in the
                     * main conf.
                     */

    //执行过初始化的shm_zones的个数，参考 ngx_http_lua_shared_memory_init
    ngx_uint_t                      shm_zones_inited;

    //用于ngx_http_lua_sema_t 对象缓存
    ngx_http_lua_sema_mm_t         *sema_mm;

    //https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#lua_malloc_trim
    //配置指令lua_malloc_trim值， 配置多少个请求后，让libc释放内存回操作系统, 默认值1000
    ngx_uint_t           malloc_trim_cycle;  /* a cycle is defined as the number
                                                of requests */
    ngx_uint_t           malloc_trim_req_count;

    ngx_uint_t           directive_line;

#if (nginx_version >= 1011011)
    /* the following 2 fields are only used by ngx.req.raw_headers() for now */
    //一个指向ngx_buf_t指针的数组
    ngx_buf_t          **busy_buf_ptrs;
    //上边的数组长度
    ngx_int_t            busy_buf_ptr_count;
#endif

    //$host 变量的索引
    ngx_int_t            host_var_index;

    //配置指令 lua_sa_restart 标识
    ngx_flag_t           set_sa_restart;

    //解析完配置后，会初始化lua_thread_cache_max_entries个元素
    //只是用于缓存 ngx_http_lua_thread_ref_t 结构体本身
    ngx_queue_t          free_lua_threads;  /* of ngx_http_lua_thread_ref_t */
    //存放的时可用的 ngx_http_lua_thread_ref_t. 从 ngx_http_lua_thread_ref_t 中
    //取出其中的lua_State和ref后，结构体放入到free_lua_threads中
    ngx_queue_t          cached_lua_threads;  /* of ngx_http_lua_thread_ref_t */

    //配置指令值 lua_worker_thread_vm_pool_size
    ngx_uint_t           worker_thread_vm_pool_size;

    //标识是否配置了header_filter_by_lua指令
    unsigned             requires_header_filter:1;
    //标识是否配置了body_filter_by_lua指令
    unsigned             requires_body_filter:1;
    unsigned             requires_capture_filter:1;
    //标识是否配置了rewrite_by_lua指令
    unsigned             requires_rewrite:1;
    //标识是否配置了access_by_lua指令
    unsigned             requires_access:1;
    //标识是否配置了log_by_lua指令
    unsigned             requires_log:1;
    //标识是否配置了lua_shared_dict指令
    unsigned             requires_shm:1;
    //标识是否配置了lua_capture_error_log指令
    unsigned             requires_capture_log:1;
    //标识是否配置了server_rewrite_by_lua指令
    unsigned             requires_server_rewrite:1;
};


struct ngx_http_lua_srv_conf_s {
    struct {
#if (NGX_HTTP_SSL)
        ngx_http_lua_srv_conf_handler_pt     ssl_cert_handler;
        ngx_str_t                            ssl_cert_src;
        u_char                              *ssl_cert_src_key;
        u_char                              *ssl_cert_chunkname;
        int                                  ssl_cert_src_ref;

        ngx_http_lua_srv_conf_handler_pt     ssl_sess_store_handler;
        ngx_str_t                            ssl_sess_store_src;
        u_char                              *ssl_sess_store_src_key;
        u_char                              *ssl_sess_store_chunkname;
        int                                  ssl_sess_store_src_ref;

        ngx_http_lua_srv_conf_handler_pt     ssl_sess_fetch_handler;
        ngx_str_t                            ssl_sess_fetch_src;
        u_char                              *ssl_sess_fetch_src_key;
        u_char                              *ssl_sess_fetch_chunkname;
        int                                  ssl_sess_fetch_src_ref;

        ngx_http_lua_srv_conf_handler_pt     ssl_client_hello_handler;
        ngx_str_t                            ssl_client_hello_src;
        u_char                              *ssl_client_hello_src_key;
        u_char                              *ssl_client_hello_chunkname;
        int                                  ssl_client_hello_src_ref;
#endif

        ngx_http_lua_srv_conf_handler_pt     server_rewrite_handler;
        ngx_http_complex_value_t             server_rewrite_src;
        u_char                              *server_rewrite_src_key;
        u_char                              *server_rewrite_chunkname;
        int                                  server_rewrite_src_ref;
    } srv;

    struct {
        //配置指令值 balancer_keepalive
        ngx_uint_t                           max_cached;
        ngx_queue_t                          cache;
        ngx_queue_t                          free;
        ngx_queue_t                         *buckets;
        ngx_uint_t                           bucket_cnt;
        ngx_http_upstream_init_pt            original_init_upstream;
        ngx_http_upstream_init_peer_pt       original_init_peer;

        ngx_http_lua_srv_conf_handler_pt     handler;
        ngx_str_t                            src;
        u_char                              *src_key;
        u_char                              *chunkname;
        int                                  src_ref;
    } balancer;
};


/***
 * ngx_http_lua_loc_conf_t loc级别的配置结构体
 * 
 * */
typedef struct {
#if (NGX_HTTP_SSL)
    ngx_ssl_t              *ssl;  /* shared by SSL cosockets */
    ngx_array_t            *ssl_certificates;
    //lua_ssl_certificate_key 配置指令的值
    ngx_array_t            *ssl_certificate_keys;
    //配置指令 lua_ssl_protocols 的值
    ngx_uint_t              ssl_protocols;
    //配置指令 lua_ssl_ciphers 的值
    ngx_str_t               ssl_ciphers;
    //配置指令 lua_ssl_verify_depth 的值
    ngx_uint_t              ssl_verify_depth;
    //配置指令 lua_ssl_trusted_certificate 的值
    ngx_str_t               ssl_trusted_certificate;
    //配置指令 lua_ssl_crl 的值
    ngx_str_t               ssl_crl;
    ngx_str_t               ssl_key_log;
#if (nginx_version >= 1019004)
    //配置指令 lua_ssl_conf_command 的值
    ngx_array_t            *ssl_conf_commands;
#endif
#endif

    //lua_need_request_body 配置指令的标识。 是否强制读取request body
    ngx_flag_t              force_read_body; /* whether force request body to
                                                be read */

    //https://openresty-reference.readthedocs.io/en/latest/Directives/#lua_code_cache
    //lua_code_cache配置指令的标识
    ngx_flag_t              enable_code_cache; /* whether to enable
                                                  code cache */

    //lua_http10_buffering 配置指令标识
    ngx_flag_t              http10_buffering;

    //llcf->rewrite_handler = (ngx_http_handler_pt) cmd->post;
    ngx_http_handler_pt     rewrite_handler;
    //llcf->access_handler = (ngx_http_handler_pt) cmd->post;
    ngx_http_handler_pt     access_handler;
    //llcf->content_handler = (ngx_http_handler_pt) cmd->post;
    ngx_http_handler_pt     content_handler;
    //llcf->log_handler = (ngx_http_handler_pt) cmd->post;
    ngx_http_handler_pt     log_handler;
    //llcf->header_filter_handler = (ngx_http_handler_pt) cmd->post;
    ngx_http_handler_pt     header_filter_handler;

    //llcf->body_filter_handler = (ngx_http_output_body_filter_pt) cmd->post;
    ngx_http_output_body_filter_pt         body_filter_handler;



    u_char                  *rewrite_chunkname;
    //rewrite_by_lua file inline script or scriptfile path
    ngx_http_complex_value_t rewrite_src;    /*  rewrite_by_lua
                                                inline script/script
                                                file path */

    u_char                  *rewrite_src_key; /* cached key for rewrite_src */
    int                      rewrite_src_ref;

    //lua代码段的chunk名称
    u_char                  *access_chunkname;
    //script file path 或 inline script 
    ngx_http_complex_value_t access_src;     /*  access_by_lua
                                                inline script/script
                                                file path */

    //cache_key
    u_char                  *access_src_key; /* cached key for access_src */
    int                      access_src_ref;

    u_char                  *content_chunkname;
    //inline script/script file path
    ngx_http_complex_value_t content_src;    /*  content_by_lua
                                                inline script/script
                                                file path */

    //cached key
    u_char                 *content_src_key; /* cached key for content_src */
    int                     content_src_ref;


    u_char                      *log_chunkname;
    ngx_http_complex_value_t     log_src;     /* log_by_lua inline script/script
                                                 file path */

    u_char                      *log_src_key; /* cached key for log_src */
    int                          log_src_ref;

    ngx_http_complex_value_t header_filter_src;  /*  header_filter_by_lua
                                                     inline script/script
                                                     file path */

    u_char                 *header_filter_chunkname;
    u_char                 *header_filter_src_key;
                                    /* cached key for header_filter_src */
    int                     header_filter_src_ref;


    ngx_http_complex_value_t         body_filter_src;
    u_char                          *body_filter_src_key;
    u_char                          *body_filter_chunkname;
    int                              body_filter_src_ref;

    ngx_msec_t                       keepalive_timeout;
    //配置指令 lua_socket_connect_timeout
    ngx_msec_t                       connect_timeout;
    //配置指令 lua_socket_send_timeout
    ngx_msec_t                       send_timeout;
    //配置指令 lua_socket_read_timeout
    ngx_msec_t                       read_timeout;

    //配置指令 lua_socket_send_lowat
    size_t                           send_lowat;
    //配置指令 lua_socket_buffer_size
    size_t                           buffer_size;

    //配置指令 lua_socket_pool_size
    ngx_uint_t                       pool_size;

    //lua_transform_underscores_in_response_headers 配置指令标识 https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#lua_transform_underscores_in_response_headers
    ngx_flag_t                       transform_underscores_in_resp_headers;
    //lua_socket_log_errors 配置指令标识
    ngx_flag_t                       log_socket_errors;
    //lua_check_client_abort 配置指令标识。是否检查client关闭连接
    ngx_flag_t                       check_client_abort;
    //lua_use_default_type 配置指令标识, 默认为on
    //https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#lua_use_default_type
    ngx_flag_t                       use_default_type;
} ngx_http_lua_loc_conf_t;


typedef enum {
    NGX_HTTP_LUA_USER_CORO_NOP      = 0,
    NGX_HTTP_LUA_USER_CORO_RESUME   = 1,
    NGX_HTTP_LUA_USER_CORO_YIELD    = 2,
    NGX_HTTP_LUA_USER_THREAD_RESUME = 3,
} ngx_http_lua_user_coro_op_t;


//协程状态
typedef enum {
    NGX_HTTP_LUA_CO_RUNNING   = 0, /* coroutine running */
    NGX_HTTP_LUA_CO_SUSPENDED = 1, /* coroutine suspended */
    NGX_HTTP_LUA_CO_NORMAL    = 2, /* coroutine normal */
    NGX_HTTP_LUA_CO_DEAD      = 3, /* coroutine dead */
    NGX_HTTP_LUA_CO_ZOMBIE    = 4, /* coroutine zombie */
} ngx_http_lua_co_status_t;


struct ngx_http_lua_posted_thread_s {
    ngx_http_lua_co_ctx_t               *co_ctx;
    ngx_http_lua_posted_thread_t        *next;
};


/**
 * lua协程上下文
 */
struct ngx_http_lua_co_ctx_s {
    //用户相关数据
    void                    *data;      /* user state for cosockets */

    //协程内部栈
    lua_State               *co;
    /** 以下三个字段为维护协程之间关系的数据 */
    //父协程
    ngx_http_lua_co_ctx_t   *parent_co_ctx;

    //僵尸子线程
    ngx_http_lua_posted_thread_t    *zombie_child_threads;
    ngx_http_lua_posted_thread_t   **next_zombie_child_thread;

    //清理函数
    ngx_http_cleanup_pt      cleanup;

    //存放多个子请求响应status的指针
    ngx_int_t               *sr_statuses; /* all capture subrequest statuses */

    //存放多个子请求响应headers的指针
    ngx_http_headers_out_t **sr_headers;

    //存放多个子请求响应体的指针
    ngx_str_t               *sr_bodies;   /* all captured subrequest bodies */

    //存放多个子请求flags的指针
    uint8_t                 *sr_flags;

    unsigned                 nresults_from_worker_thread;  /* number of results
                                                            * from worker
                                                            * thread callback */
    unsigned                 nrets;     /* ngx_http_lua_run_thread nrets arg. */

    //子请求数量
    unsigned                 nsubreqs;  /* number of subrequests of the
                                         * current request */

    //等待结束的子请求数量
    unsigned                 pending_subreqs; /* number of subrequests being
                                                 waited */

    //用于ngx.sleep的定时事件对象， 事件的handler为 ngx_http_lua_sleep_handler
    ngx_event_t              sleep;  /* used for ngx.sleep */


    //当指向semaphore:wait()时，用于将当前协程加入到ngx_http_lua_sema_s->wait_queue中
    ngx_queue_t              sem_wait_queue;

#ifdef NGX_LUA_USE_ASSERT
    int                      co_top; /* stack top after yielding/creation,
                                        only for sanity checks */
#endif

    //在Lua的registry表中对应该线程指针的引用值
    int                      co_ref; /*  reference to anchor the thread
                                         coroutines (entry coroutine and user
                                         threads) in the Lua registry,
                                         preventing the thread coroutine
                                         from beging collected by the
                                         Lua GC */

    //标识当前协程是否正在被父协程wait.如ngx.thread.wait(thread1,thread2,...)
    unsigned                 waited_by_parent:1;  /* whether being waited by
                                                     a parent coroutine */

    //当前协程的运行状态
    unsigned                 co_status:3;  /* the current coroutine's status */

    unsigned                 flushing:1; /* indicates whether the current
                                            coroutine is waiting for
                                            ngx.flush(true) */

    //是否是用户线程，即通过ngx.thread.spawn()方法创建的
    unsigned                 is_uthread:1; /* whether the current coroutine is
                                              a user thread */

    unsigned                 thread_spawn_yielded:1; /* yielded from
                                                        the ngx.thread.spawn()
                                                        call */
    //标识当前协程semaphore:wait后，重新resume的原因，0：为等到了可用资源;1:为等待超时
    unsigned                 sem_resume_status:1;

    unsigned                 is_wrap:1; /* set when creating coroutines via
                                           coroutine.wrap */

    unsigned                 propagate_error:1; /* set when propagating an error
                                                   from a coroutine to its
                                                   parent */
};


typedef struct {
    lua_State       *vm;
    //引用次数
    ngx_int_t        count;
} ngx_http_lua_vm_state_t;


/**
 * ngx_http_lua_module 上下文结构体
 */
typedef struct ngx_http_lua_ctx_s {
    /* for lua_code_cache off: */
    //如果关闭了lua_code_cache, 则这个字段指向针对每个请求新创建的 ngx_http_lua_vm_state_t;否则此字段为NULL
    //参考 ngx_http_lua_create_ctx() 
    ngx_http_lua_vm_state_t  *vm_state;

    ngx_http_request_t      *request;
    /**
     * 如果第一次执行被yield，再次执行会调用此resume_handler继续执行原来的逻辑
     * ngx_http_lua_content_handler中会调用此方法
     * 
     *   if (ctx->entered_content_phase) {
     *       rc = ctx->resume_handler(r);
     *       return rc;
     *   }
     */
    ngx_http_handler_pt      resume_handler;

    /* 当前协程上下文信息 */
    ngx_http_lua_co_ctx_t   *cur_co_ctx; /* co ctx for the current coroutine */

    /* 用户创建的协程上下文信息列表 */
    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */
    ngx_list_t              *user_co_ctx; /* coroutine contexts for user
                                             coroutines */

    /* 请求入口协程上下文信息。执行配置指令中配置的lua代码时创建的协程 */
    ngx_http_lua_co_ctx_t    entry_co_ctx; /* coroutine context for the
                                              entry coroutine */

    //ngx.on_abort() 如果调用过此api, 则此字段不为NULL。
    //客户端提前关闭连接时执行的lua层的回调，此字段是一个协程执行上下文
    ngx_http_lua_co_ctx_t   *on_abort_co_ctx; /* coroutine context for the
                                                 on_abort thread */

    //ngx.ctx变量的索引。在lua层有个ctxs数组，此ctx_ref记录了本次请求的ngx.ctx在ctxs数组中的索引
    int                      ctx_ref;  /*  reference to anchor
                                           request ctx data in lua
                                           registry */

    unsigned                 flushing_coros; /* number of coroutines waiting on
                                                ngx.flush(true) */

    ngx_chain_t             *out;  /* buffered output chain for HTTP 1.0 */
    ngx_chain_t             *free_bufs;
    ngx_chain_t             *busy_bufs;
    ngx_chain_t             *free_recv_bufs;

    ngx_chain_t             *filter_in_bufs;  /* for the body filter */
    ngx_chain_t             *filter_busy_bufs;  /* for the body filter */

    ngx_pool_cleanup_pt     *cleanup;

    ngx_http_cleanup_t      *free_cleanup; /* free list of cleanup records */

    ngx_chain_t             *body; /* buffered subrequest response body
                                      chains */

    ngx_chain_t            **last_body; /* for the "body" field */

    //调用ngx.exec() 函数设置的uri
    ngx_str_t                exec_uri;
     //调用ngx.exec() 函数设置的args
    ngx_str_t                exec_args;

    //响应状态码。如ngx.exit()
    ngx_int_t                exit_code;

    void                    *downstream;  /* can be either
                                             ngx_http_lua_socket_tcp_upstream_t
                                             or ngx_http_lua_co_ctx_t */

    //子请求在父请求的所有子请求中的索引
    ngx_uint_t               index;              /* index of the current
                                                    subrequest in its parent
                                                    request */

    //
    ngx_http_lua_posted_thread_t   *posted_threads;

    //ngx.thread.spawn()方法创建的uthreads总数
    int                      uthreads; /* number of active user threads */

    //定义了16种context, 如 NGX_HTTP_LUA_CONTEXT_ACCESS
    //这个成员变量在各个 phase 的 Lua handler 内，Lua 代码执行之前被赋值
    uint16_t                 context;   /* the current running directive context
                                           (or running phase) for the current
                                           Lua chunk */

    //标识子请求是否已经执行过ngx_http_lua_post_subrequest(子请求执行结束后的回调方法)了
    unsigned                 run_post_subrequest:1; /* whether it has run
                                                       post_subrequest
                                                       (for subrequests only) */

    //标识当前正在等待读取更多请求体
    unsigned                 waiting_more_body:1;   /* 1: waiting for more
                                                       request body data;
                                                       0: no need to wait */

    //代表协程yield的原因
    //其值为NGX_HTTP_LUA_USER_CORO_NOP时表明是由于ngx.socket或者ngx.sleep导致的
    unsigned         co_op:2; /*  coroutine API operation */

    //标识已经调用了ngx.exit(status)
    unsigned         exited:1;

    //标识是否已经发送了eof了 ngx.eof方法
    unsigned         eof:1;             /*  1: last_buf has been sent;
                                            0: last_buf not sent yet */

    unsigned         capture:1;  /*  1: response body of current request
                                        is to be captured by the lua
                                        capture filter,
                                     0: not to be captured */


    //是否已经全部读取了请求体
    unsigned         read_body_done:1;      /* 1: request body has been all
                                               read; 0: body has not been
                                               all read */

    //是否通过ngx.header.HEADER api重新设置了响应头，参考ngx_http_lua_ffi_set_resp_header方法
    unsigned         headers_set:1; /* whether the user has set custom
                                       response headers */
    //是否通过ngx.header.HEADER api重新设置了 Content-Type 响应头
    unsigned         mime_set:1;    /* whether the user has set Content-Type
                                       response header */
    unsigned         entered_server_rewrite_phase:1;
    unsigned         entered_rewrite_phase:1;
    unsigned         entered_access_phase:1;
    //标识是否已经进入content阶段了。conetnt_by_lua* 的content_handler 中会将此值置1
    //标识conetnt_by_lua中的lua代码已经开始执行了
    unsigned         entered_content_phase:1;

    unsigned         buffering:1; /* HTTP 1.0 response body buffering flag */

    //标识有ngx.location.capture_multi()发起的子请求
    unsigned         no_abort:1; /* prohibit "world abortion" via ngx.exit()
                                    and etc */

    //标识header是否已经发送了
    unsigned         header_sent:1; /* r->header_sent is not sufficient for
                                     * this because special header filters
                                     * like ngx_image_filter may intercept
                                     * the header. so we should always test
                                     * both flags. see the test case in
                                     * t/020-subrequest.t */

    unsigned         seen_last_in_filter:1;  /* used by body_filter_by_lua* */
    unsigned         seen_last_for_subreq:1; /* used by body capture filter */
    unsigned         writing_raw_req_socket:1; /* used by raw downstream
                                                  socket */
    //标识是否已经调用过ngx.req.socket()方法了
    unsigned         acquired_raw_req_socket:1;  /* whether a raw req socket
                                                    is acquired */
    unsigned         seen_body_data:1;
} ngx_http_lua_ctx_t;


struct ngx_http_lua_header_val_s {
    ngx_http_complex_value_t                value;
    ngx_uint_t                              hash;
    ngx_str_t                               key;
    ngx_http_lua_set_header_pt              handler;
    ngx_uint_t                              offset;
    unsigned                                no_override;
};


/**
 * 参考 ngx_http_lua_set_handlers 数组
 * 代表一个需要预处理的请求头
 * 在发起子请求时，会复制所有父请求的请求头。对于一些预定义的请求头，调用handler方法进行额外处理
 */
typedef struct {
    //header key
    ngx_str_t                               name;
    //当前header在ngx_http_headers_in_t中字段offset；如 offsetof(ngx_http_headers_in_t, host)
    ngx_uint_t                              offset;
    //handler。
    ngx_http_lua_set_header_pt              handler;
} ngx_http_lua_set_header_t;


extern ngx_module_t ngx_http_lua_module;
extern ngx_http_output_header_filter_pt ngx_http_lua_next_header_filter;
extern ngx_http_output_body_filter_pt ngx_http_lua_next_body_filter;


#endif /* _NGX_HTTP_LUA_COMMON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
