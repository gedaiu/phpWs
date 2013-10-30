PHP_ARG_ENABLE(websockets, whether to enable php websocket extension,
[ --enable-websockets   Enable php websoket module])
 
if test "$PHP_WEBSOCKETS" = "yes"; then
	PHP_REQUIRE_CXX()
	PHP_ADD_LIBRARY(stdc++, 1, WEBSOCKETS_SHARED_LIBADD)

	PHP_ADD_INCLUDE(/usr/include/php/sapi/apache2handler)
	PHP_ADD_INCLUDE(/usr/include/php/sapi/apache_hooks)
	PHP_ADD_INCLUDE(/usr/include/httpd)
	PHP_ADD_INCLUDE(/usr/include/apr-1)

	PHP_NEW_EXTENSION(websockets, websockets.c wsFrame.c wsServer.c, $ext_shared)
fi
