PHP_ARG_ENABLE(websockets, whether to enable php websocket extension,
[ --enable-websockets   Enable php websoket module])

PHP_ARG_WITH(websockets-php-includes, the path to use for websocket extension includes,
[ --with-websockets-php-includes The path to the php-src directory for extra websocket includes], no)

PHP_ARG_WITH(websockets-httpd-includes, the path to use for websocket httpd includes,
[ --with-websockets-httpd-includes The path to the php-src directory for httpd websocket includes], no)


if test "$PHP_WEBSOCKETS" = "yes"; then
	PHP_REQUIRE_CXX()
	PHP_ADD_LIBRARY(stdc++, 1, WEBSOCKETS_SHARED_LIBADD)

  if test "x$PHP_WEBSOCKETS_PHP_INCLUDES" == "xno" || test "x$PHP_WEBSOCKETS_PHP_INCLUDES" == "xyes"; then
    PHP_WEBSOCKETS_PHP_INCLUDES=/usr/include/php
  fi
  
  if test "x$PHP_WEBSOCKETS_HTTPD_INCLUDES" == "xno" || test "x$PHP_WEBSOCKETS_HTTPD_INCLUDES" == "xyes"; then
    PHP_WEBSOCKETS_HTTPD_INCLUDES=/usr/include
  fi

	PHP_ADD_INCLUDE(${PHP_WEBSOCKETS_PHP_INCLUDES}/sapi/apache2handler)
	PHP_ADD_INCLUDE(${PHP_WEBSOCKETS_PHP_INCLUDES}/sapi/apache_hooks)
	PHP_ADD_INCLUDE(${PHP_WEBSOCKETS_HTTPD_INCLUDES}/httpd)
	PHP_ADD_INCLUDE(${PHP_WEBSOCKETS_HTTPD_INCLUDES}/apr-1)

	PHP_NEW_EXTENSION(websockets, websockets.c wsFrame.c wsServer.c, $ext_shared)
fi
