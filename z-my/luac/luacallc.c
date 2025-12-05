#include <stdio.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
 
LUALIB_API int luaopen_mylib(lua_State *L );
 
//自定义函数
static int my_add(lua_State *L)
{
    int x = lua_tonumber(L,1); //第一个参数,转换为数字
    int y = lua_tonumber(L,2); //第二个参数,转换为数字
    int sum = x + y;
    lua_pushnumber(L, sum);
    return 1; //返回sum计算结果
}
 
static int showstr(lua_State *L)
{
   //从lua中传入的第一个参数
   const char *str = lua_tostring(L, 1);
 
   printf ("c program str = %s\n", str);
   return 0;
}
 
//函数列表
static luaL_Reg funclist[] =
{
    {"add", my_add}, //my_add()函数，lua中访问时使用名称为add
    {"show", showstr}, //showstr()函数，lua中访问时使用名称为show
    {NULL, NULL}  //最后必须有这个
};
 
//注册函数列表方便扩展
//我们编译后的动态库名称为mylib.so
LUALIB_API int luaopen_mylib(lua_State *L )
{
    luaL_register(L, "mylibfunc", funclist); //lua中使用mylibfunc.add访问my_add函数
    return 1;
}
 
#if 0
//直接注册一个函数
LUALIB_API int luaopen_mylib(lua_State *L )
{
    lua_register(L, "add", my_add);
    return 1;
}
#endif
