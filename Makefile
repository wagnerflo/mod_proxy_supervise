all: .libs/mod_proxy_spawn.so

.libs/mod_proxy_spawn.so: mod_proxy_spawn.c
	apxs -c $<
