all: .libs/mod_proxy_spawn.so

.libs/mod_proxy_spawn.so: mod_proxy_spawn.c
	apxs -c -I../libs7e/include -L../libs7e -ls7e $<
