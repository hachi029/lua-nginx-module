#include <stdio.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
//gcc -I /usr/local/Cellar/openresty/1.21.4.1_1/luajit/include/luajit-2.1 -L/usr/local/Cellar/openresty/1.21.4.1_1/luajit/lib -ldl -lluajit  lua_ref.c
const char script[] = "print('Hello, Lua!')";

int main(void) {
    /* 创建一个全局的global_State结构和代表一个协程的lua_State结构，lua_State作为主协程返回 */
    lua_State   *L = luaL_newstate();
    if (!L) return -1;

    /*  将print, math，string,table等Lua内置的函数库注册到协程中 */
    luaL_openlibs(L);

    /*  加载一段Lua代码，将其编译成Lua虚拟机的字节码 */
    int ret = luaL_loadstring(L, script);
    if (ret != 0) {
        return -1;
    }

    /*  在Lua虚拟机中执行前面加载的Lua代码 */
    //ret = lua_pcall(L, 0, LUA_MULTRET, 0);
    ret = lua_resume(L, 0);
    if (ret != 0) {
        return -1;
    }

    lua_close(L);

    return 0;
}
