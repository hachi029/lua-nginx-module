
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) cuiweixie
 * I hereby assign copyright in this code to the lua-nginx-module project,
 * to be licensed under the same terms as the rest of the code.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_util.h"
#include "ngx_http_lua_semaphore.h"
#include "ngx_http_lua_contentby.h"


ngx_int_t ngx_http_lua_sema_mm_init(ngx_conf_t *cf,
    ngx_http_lua_main_conf_t *lmcf);
void ngx_http_lua_sema_mm_cleanup(void *data);
static ngx_http_lua_sema_t *ngx_http_lua_alloc_sema(void);
static void ngx_http_lua_free_sema(ngx_http_lua_sema_t *sem);
static ngx_int_t ngx_http_lua_sema_resume(ngx_http_request_t *r);
int ngx_http_lua_ffi_sema_new(ngx_http_lua_sema_t **psem,
    int n, char **errmsg);
int ngx_http_lua_ffi_sema_post(ngx_http_lua_sema_t *sem, int n);
int ngx_http_lua_ffi_sema_wait(ngx_http_request_t *r,
    ngx_http_lua_sema_t *sem, int wait_ms, u_char *err, size_t *errlen);
static void ngx_http_lua_sema_cleanup(void *data);
static void ngx_http_lua_sema_handler(ngx_event_t *ev);
static void ngx_http_lua_sema_timeout_handler(ngx_event_t *ev);
void ngx_http_lua_ffi_sema_gc(ngx_http_lua_sema_t *sem);


//标识协程semaphore:wait后，重新resume的原因。参考 co_ctx->sem_resume_status
enum {
    //等待到了可用资源
    SEMAPHORE_WAIT_SUCC = 0,
    //等待超时
    SEMAPHORE_WAIT_TIMEOUT = 1,
};


/**
 * 初始化 lmcf->sema_mm 结构体 ngx_http_lua_sema_mm_t ， 用于semaphore对象缓存/管理
 */
ngx_int_t
ngx_http_lua_sema_mm_init(ngx_conf_t *cf, ngx_http_lua_main_conf_t *lmcf)
{
    ngx_http_lua_sema_mm_t *mm;

    //创建 ngx_http_lua_sema_mm_t
    mm = ngx_palloc(cf->pool, sizeof(ngx_http_lua_sema_mm_t));
    if (mm == NULL) {
        return NGX_ERROR;
    }

    //互相指向
    lmcf->sema_mm = mm;
    mm->lmcf = lmcf;

    //初始化缓存队列
    ngx_queue_init(&mm->free_queue);
    mm->cur_epoch = 0;
    mm->total = 0;
    mm->used = 0;

    /* it's better to be 4096, but it needs some space for
     * ngx_http_lua_sema_mm_block_t, one is enough, so it is 4095
     */
    mm->num_per_block = 4095;

    return NGX_OK;
}


/**
 * 分配一个 ngx_http_lua_sema_t 对象
 * 
 * 包含 ngx_http_lua_sema_t 的缓存逻辑
 *  1.先尝试从 lmcf->sema_mm 中的缓存队列中取出一个空闲的结构体
 *  2.一次性创建一个包含多个 ngx_http_lua_sema_t 的block
 *  3.把block中第一个 ngx_http_lua_sema_t 返回，其余的放到lmcf->sema_mm->free_queue
 */
static ngx_http_lua_sema_t *
ngx_http_lua_alloc_sema(void)
{
    ngx_uint_t                           i, n;
    ngx_queue_t                         *q;
    ngx_http_lua_sema_t                 *sem, *iter;
    ngx_http_lua_sema_mm_t              *mm;
    ngx_http_lua_main_conf_t            *lmcf;
    ngx_http_lua_sema_mm_block_t        *block;

    ngx_http_lua_assert(ngx_cycle && ngx_cycle->conf_ctx);

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_lua_module);

    ngx_http_lua_assert(lmcf != NULL);

    //先尝试从缓存队列中去一个空闲的ngx_http_lua_sema_t对象
    mm = lmcf->sema_mm;

    if (!ngx_queue_empty(&mm->free_queue)) {
        q = ngx_queue_head(&mm->free_queue);
        ngx_queue_remove(q);

        sem = ngx_queue_data(q, ngx_http_lua_sema_t, chain);

        sem->block->used++;

        //事件重置
        ngx_memzero(&sem->sem_event, sizeof(ngx_event_t));

        //设置事件处理函数
        sem->sem_event.handler = ngx_http_lua_sema_handler;
        sem->sem_event.data = sem;
        sem->sem_event.log = ngx_cycle->log;

        mm->used++;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "from head of free queue, alloc semaphore: %p", sem);

        return sem;
    }
    //创建新的结构体 ngx_http_lua_sema_t

    /* free_queue is empty */

    //一次分配mm->num_per_block个 ngx_http_lua_sema_t 对象
    n = sizeof(ngx_http_lua_sema_mm_block_t)
        + mm->num_per_block * sizeof(ngx_http_lua_sema_t);

    dd("block size: %d, item size: %d",
       (int) sizeof(ngx_http_lua_sema_mm_block_t),
       (int) sizeof(ngx_http_lua_sema_t));

    //分配内存
    block = ngx_alloc(n, ngx_cycle->log);
    if (block == NULL) {
        return NULL;
    }

    mm->cur_epoch++;
    //总共分配的 ngx_http_lua_sema_t 结构体数量
    mm->total += mm->num_per_block;
    mm->used++;

    block->mm = mm;
    block->epoch = mm->cur_epoch;

    //获取block的第一个 ngx_http_lua_sema_t 结构体
    sem = (ngx_http_lua_sema_t *) (block + 1);
    sem->block = block;
    sem->block->used = 1;

    ngx_memzero(&sem->sem_event, sizeof(ngx_event_t));

    //设置事件处理函数
    sem->sem_event.handler = ngx_http_lua_sema_handler;
    sem->sem_event.data = sem;
    sem->sem_event.log = ngx_cycle->log;

    //将其余的 ngx_http_lua_sema_t 结构体加入到 mm->free_queue 队列
    for (iter = sem + 1, i = 1; i < mm->num_per_block; i++, iter++) {
        //设置所属的block
        iter->block = block;
        ngx_queue_insert_tail(&mm->free_queue, &iter->chain);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "new block, alloc semaphore: %p block: %p", sem, block);

    return sem;
}


/**
 * 在ngx_http_lua_init()函数中在cf->pool上添加的一个清理函数， data是ngx_http_lua_main_conf_t
 * 
 * 用于释放 ngx_http_lua_main_conf_t->sema_mm 队列
 * */
void
ngx_http_lua_sema_mm_cleanup(void *data)
{
    ngx_uint_t                           i;
    ngx_queue_t                         *q;
    ngx_http_lua_sema_t                 *sem, *iter;
    ngx_http_lua_sema_mm_t              *mm;
    ngx_http_lua_main_conf_t            *lmcf;
    ngx_http_lua_sema_mm_block_t        *block;

    lmcf = (ngx_http_lua_main_conf_t *) data;
    mm = lmcf->sema_mm;

    //遍历free_queue
    while (!ngx_queue_empty(&mm->free_queue)) {
        q = ngx_queue_head(&mm->free_queue);

        sem = ngx_queue_data(q, ngx_http_lua_sema_t, chain);
        block = sem->block;

        ngx_http_lua_assert(block != NULL);

        //如果block已空
        if (block->used == 0) {
            iter = (ngx_http_lua_sema_t *) (block + 1);

            //将所有节点从&mm->free_queue移除
            for (i = 0; i < block->mm->num_per_block; i++, iter++) {
                ngx_queue_remove(&iter->chain);
            }

            dd("free sema block: %p at final", block);

            //释放内存
            ngx_free(block);

        } else {
            /* just return directly when some thing goes wrong */

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "lua sema mm: freeing a block %p that is still "
                          " used by someone", block);

            return;
        }
    }

    dd("lua sema mm cleanup done");
}


/**
 * ngx_http_lua_ffi_sema_gc->.
 * 
 * 释放 ngx_http_lua_sema_t 结构体。将其重新加入到缓存队列中
 */
static void
ngx_http_lua_free_sema(ngx_http_lua_sema_t *sem)
{
    ngx_http_lua_sema_t            *iter;
    ngx_uint_t                      i, mid_epoch;
    ngx_http_lua_sema_mm_block_t   *block;
    ngx_http_lua_sema_mm_t         *mm;

    block = sem->block;
    //当前block使用的 ngx_http_lua_sema_t 结构体个数-1
    block->used--;

    mm = block->mm;
    //当前全局正在使用中的 ngx_http_lua_sema_t 结构体个数-1
    mm->used--;

    mid_epoch = mm->cur_epoch - ((mm->total / mm->num_per_block) >> 1);

    if (block->epoch < mid_epoch) {
        //加入到free_queue的尾部
        ngx_queue_insert_tail(&mm->free_queue, &sem->chain);
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "add to free queue tail semaphore: %p epoch: %d"
                       "mid_epoch: %d cur_epoch: %d", sem, (int) block->epoch,
                       (int) mid_epoch, (int) mm->cur_epoch);

    } else {
        //加入到free_queue的头部
        ngx_queue_insert_head(&mm->free_queue, &sem->chain);
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "add to free queue head semaphore: %p epoch: %d"
                       "mid_epoch: %d cur_epoch: %d", sem, (int) block->epoch,
                       (int) mid_epoch, (int) mm->cur_epoch);
    }

    dd("used: %d", (int) block->used);

    //如果block已空
    if (block->used == 0
        //且使用中的 ngx_http_lua_sema_t 个数小于总个数一半(闲置率>50%)
        && mm->used <= (mm->total >> 1)
        && block->epoch < mid_epoch)
    {
        /* load <= 50% and it's on the older side */
        iter = (ngx_http_lua_sema_t *) (block + 1);

        for (i = 0; i < mm->num_per_block; i++, iter++) {
            //将其从&mm->free_queue中移除
            ngx_queue_remove(&iter->chain);
        }

        //更新总的 ngx_http_lua_sema_t 个数
        mm->total -= mm->num_per_block;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "free semaphore block: %p", block);

        //释放内存
        ngx_free(block);
    }
}


/**
 * 恢复协程运行
 */
static ngx_int_t
ngx_http_lua_sema_resume(ngx_http_request_t *r)
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

    //重新设置resume_handler
    ctx->resume_handler = ngx_http_lua_wev_handler;

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    //设置wait的返回值
    if (ctx->cur_co_ctx->sem_resume_status == SEMAPHORE_WAIT_SUCC) {
        lua_pushboolean(ctx->cur_co_ctx->co, 1);
        lua_pushnil(ctx->cur_co_ctx->co);

    } else {
        lua_pushboolean(ctx->cur_co_ctx->co, 0);
        lua_pushliteral(ctx->cur_co_ctx->co, "timeout");
    }

    //执行协程
    rc = ngx_http_lua_run_thread(vm, r, ctx, 2);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NGX_DONE) {
        ngx_http_lua_finalize_request(r, NGX_DONE);
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    /* rc == NGX_ERROR || rc >= NGX_OK */

    if (ctx->entered_content_phase) {
        ngx_http_lua_finalize_request(r, rc);
        return NGX_DONE;
    }

    return rc;
}


/**
 * syntax: sema, err = semaphore_module.new(n?)
 */
int
ngx_http_lua_ffi_sema_new(ngx_http_lua_sema_t **psem,
    int n, char **errmsg)
{
    ngx_http_lua_sema_t    *sem;

    //申请一个 ngx_http_lua_sema_t 结构体
    sem = ngx_http_lua_alloc_sema();
    if (sem == NULL) {
        *errmsg = "no memory";
        return NGX_ERROR;
    }

    //初始化等待队列
    ngx_queue_init(&sem->wait_queue);

    //初始化资源个数
    sem->resource_count = n;
    sem->wait_count = 0;
    *psem = sem;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http lua semaphore new: %p, resources: %d",
                   sem, sem->resource_count);

    return NGX_OK;
}


/**
 * syntax: sema:post(n?)
 */
int
ngx_http_lua_ffi_sema_post(ngx_http_lua_sema_t *sem, int n)
{
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http lua semaphore post: %p, n: %d, resources: %d",
                   sem, n, sem->resource_count);

    //将可用资源个数+n
    sem->resource_count += n;

    //如果等待队列不为空，则触发
    if (!ngx_queue_empty(&sem->wait_queue)) {
        /* we need the extra parentheses around the first argument of
         * ngx_post_event() just to work around macro issues in nginx
         * cores older than nginx 1.7.12 (exclusive).
         */
        //将事件加入到 ngx_posted_events 队列中
        //sem_event->handler = ngx_http_lua_sema_handler
        ngx_post_event((&sem->sem_event), &ngx_posted_events);
    }

    return NGX_OK;
}


/**
 * syntax: ok, err = sema:wait(timeout)
 * 
 * 返回：
 *  NGX_ERROR：出错
 *  NGX_OK：成功等待到资源
 *  NGX_DECLINED：超时返回
 */
int
ngx_http_lua_ffi_sema_wait(ngx_http_request_t *r,
    ngx_http_lua_sema_t *sem, int wait_ms, u_char *err, size_t *errlen)
{
    ngx_http_lua_ctx_t           *ctx;
    ngx_http_lua_co_ctx_t        *wait_co_ctx;
    ngx_int_t                     rc;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http lua semaphore wait: %p, timeout: %d, "
                   "resources: %d, event posted: %d",
                   sem, wait_ms, sem->resource_count,
#if (nginx_version >= 1007005)
                   (int) sem->sem_event.posted
#else
                   sem->sem_event.prev ? 1 : 0
#endif
                   );

    //获取模块上下文结构体
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        *errlen = ngx_snprintf(err, *errlen, "no request ctx found") - err;
        return NGX_ERROR;
    }

    // context: rewrite_by_lua*, access_by_lua*, content_by_lua*, ngx.timer.*
    rc = ngx_http_lua_ffi_check_context(ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE,
                                        err, errlen);

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* we keep the order, will first resume the thread waiting for the
     * longest time in ngx_http_lua_sema_handler
     */

    //如果等待队列为空，且有可用资源
    if (ngx_queue_empty(&sem->wait_queue) && sem->resource_count > 0) {
        //可用资源数-1，直接返回
        sem->resource_count--;
        return NGX_OK;
    }

    //等待时间为0，直接返回
    if (wait_ms == 0) {
        return NGX_DECLINED;
    }

    //等待的协程数量+1
    sem->wait_count++;
    //当前协程上下文
    wait_co_ctx = ctx->cur_co_ctx;

    //设置sleep的事件处理函数
    wait_co_ctx->sleep.handler = ngx_http_lua_sema_timeout_handler;
    //data设置为当前协程的上下文
    wait_co_ctx->sleep.data = ctx->cur_co_ctx;
    wait_co_ctx->sleep.log = r->connection->log;

    //添加一个timer，超时事件为wait_ms
    ngx_add_timer(&wait_co_ctx->sleep, (ngx_msec_t) wait_ms);

    dd("ngx_http_lua_ffi_sema_wait add timer coctx:%p wait: %d(ms)",
       wait_co_ctx, wait_ms);

    //加入到等待队列
    ngx_queue_insert_tail(&sem->wait_queue, &wait_co_ctx->sem_wait_queue);

    wait_co_ctx->data = sem;
    wait_co_ctx->cleanup = ngx_http_lua_sema_cleanup;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http lua semaphore wait yielding");

    //返回NGX_AGAIN, 在lua代码中进行yield
    return NGX_AGAIN;
}


/**
 * syntax: count = sema:count()
 */
int
ngx_http_lua_ffi_sema_count(ngx_http_lua_sema_t *sem)
{
    //可用资源数量-当前等待协程数量
    return sem->resource_count - sem->wait_count;
}


/**
 * *data为协程执行上下文
 * 清理 data 指向的协程在semaphore上相关资源
 */
static void
ngx_http_lua_sema_cleanup(void *data)
{
    ngx_http_lua_co_ctx_t          *coctx = data;
    ngx_queue_t                    *q;
    ngx_http_lua_sema_t            *sem;

    sem = coctx->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http lua semaphore cleanup");

    //如果协程的sleep事件仍然在定时器中，则将其从定时器中删除
    if (coctx->sleep.timer_set) {
        ngx_del_timer(&coctx->sleep);
    }

    //将协程从等待队列中移除
    q = &coctx->sem_wait_queue;

    ngx_queue_remove(q);
    //所在的semaphore上的等待协程数-1
    sem->wait_count--;
    coctx->cleanup = NULL;
}


/**
 * semaphore 对象的事件处理函数， 
 * 参考 ngx_http_lua_alloc_sema 和 ngx_http_lua_ffi_sema_post 方法
 */
static void
ngx_http_lua_sema_handler(ngx_event_t *ev)
{
    ngx_http_lua_sema_t         *sem;
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *wait_co_ctx;
    ngx_connection_t            *c;
    ngx_queue_t                 *q;

    sem = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "semaphore handler: wait queue: %sempty, resource count: %d",
                   ngx_queue_empty(&sem->wait_queue) ? "" : "not ",
                   sem->resource_count);
    //如果等待队列不为空，且还有可用的资源
    while (!ngx_queue_empty(&sem->wait_queue) && sem->resource_count > 0) {
        //从等待队列中取出首个元素
        q = ngx_queue_head(&sem->wait_queue);
        ngx_queue_remove(q);

        //等待数量-1
        sem->wait_count--;

        wait_co_ctx = ngx_queue_data(q, ngx_http_lua_co_ctx_t, sem_wait_queue);
        wait_co_ctx->cleanup = NULL;

        //从定时器中移除
        if (wait_co_ctx->sleep.timer_set) {
            ngx_del_timer(&wait_co_ctx->sleep);
        }

        r = ngx_http_lua_get_req(wait_co_ctx->co);
        c = r->connection;

        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
        ngx_http_lua_assert(ctx != NULL);

        //资源数量-1
        sem->resource_count--;

        //将当前协程置为等待队列中的协程
        ctx->cur_co_ctx = wait_co_ctx;

        //设置重新开始执行的原因为 SEMAPHORE_WAIT_SUCC 
        wait_co_ctx->sem_resume_status = SEMAPHORE_WAIT_SUCC;

        //恢复协程运行
        if (ctx->entered_content_phase) {
            (void) ngx_http_lua_sema_resume(r);

        } else {
            ctx->resume_handler = ngx_http_lua_sema_resume;
            ngx_http_core_run_phases(r);
        }

        ngx_http_run_posted_requests(c);
    }
}


/**
 * 参考 ngx_http_lua_ffi_sema_wait 
 * 当smeaphore:wait 需要等待时，注册一个sleep事件，此函数为事件超时的处理函数
 */
static void
ngx_http_lua_sema_timeout_handler(ngx_event_t *ev)
{
    ngx_http_lua_co_ctx_t       *wait_co_ctx;
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_connection_t            *c;
    ngx_http_lua_sema_t         *sem;

    wait_co_ctx = ev->data;
    wait_co_ctx->cleanup = NULL;

    dd("ngx_http_lua_sema_timeout_handler timeout coctx:%p", wait_co_ctx);

    sem = wait_co_ctx->data;

    //将当前协程从semaphore的等待队列中移除
    ngx_queue_remove(&wait_co_ctx->sem_wait_queue);
    //semaphore的等待协程数-1
    sem->wait_count--;

    r = ngx_http_lua_get_req(wait_co_ctx->co);
    c = r->connection;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    ngx_http_lua_assert(ctx != NULL);

    //设置 cur_co_ctx
    ctx->cur_co_ctx = wait_co_ctx;

    //设置resume_status 为 超时
    wait_co_ctx->sem_resume_status = SEMAPHORE_WAIT_TIMEOUT;

   //恢复协程运行
    if (ctx->entered_content_phase) {
        (void) ngx_http_lua_sema_resume(r);

    } else {
        ctx->resume_handler = ngx_http_lua_sema_resume;
        ngx_http_core_run_phases(r);
    }

    ngx_http_run_posted_requests(c);
}


/**
 * ffi_gc(sem, ngx_lua_ffi_sema_gc)
 * 
 * 绑定到semaphore上的析构函数。用于释放 ngx_http_lua_sema_t 结构体
 */
void
ngx_http_lua_ffi_sema_gc(ngx_http_lua_sema_t *sem)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "in lua gc, semaphore %p", sem);

    if (sem == NULL) {
        return;
    }

    if (!ngx_terminate
        && !ngx_quit
        && !ngx_queue_empty(&sem->wait_queue))
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "in lua semaphore gc wait queue is"
                      " not empty while the semaphore %p is being "
                      "destroyed", sem);
    }

    if (sem->sem_event.posted) {
        ngx_delete_posted_event(&sem->sem_event);
    }

    //释放表示一个semaphore的 ngx_http_lua_sema_t 结构体
    ngx_http_lua_free_sema(sem);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
