#ifndef PHP_WEBSOCKETS_H
#define PHP_WEBSOCKETS_H 1

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>      /* base64 encode/decode */
#include <openssl/md5.h> /* md5 hash */
#include <openssl/sha.h> /* sha1 hash */
#include "php.h"
#include "ext/standard/php_standard.h"
#include "ext/date/php_date.h"
#include "php_main.h"

#include "php_apache_http.h"
#include "php_apache.h"

#include "SAPI.h"


#ifdef TM_IN_SYS_TIME
	#include <sys/time.h>
#else
	#include <time.h>
#endif

#define PHP_WEBSOCKETS_VERSION "1.0"
#define PHP_WEBSOCKETS_EXTNAME "websockets" 

#define	HYBI10_ACCEPTHDRLEN	29

PHP_FUNCTION(is_ws);
PHP_FUNCTION(ws_handshake);
PHP_FUNCTION(ws_send);
PHP_FUNCTION(ws_receive);
PHP_FUNCTION(ws_close);

extern zend_module_entry websockets_module_entry;
#define phpext_websockets_ptr &websockets_module_entry

ZEND_BEGIN_MODULE_GLOBALS(websockets)
	char* temp_buffer;
ZEND_END_MODULE_GLOBALS(websockets)

#ifdef ZTS
#define WS_G(v) TSRMG(websockets_globals_id, zend_websockets_globals *, v)
#else
#define WS_G(v) (websockets_globals.v)
#endif


#define http_got_server_var(v) (NULL != http_get_server_var_ex((v), strlen(v), 1))
#define http_get_server_var(v, c) http_get_server_var_ex((v), strlen(v), (c))
#define http_get_server_var_ex(v, l, c) _http_get_server_var_ex((v), (l), (c) TSRMLS_CC) 

#endif 
