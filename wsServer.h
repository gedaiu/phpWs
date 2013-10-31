#ifndef PHP_HTTP_WSSERVER_H
#define PHP_HTTP_WSSERVER_H

#include "php.h"
#include "php_main.h"

#include "httpd.h"
#include "php_apache_http.h"
#include "php_apache.h"
#include "ext/standard/php_smart_str.h"
#include "SAPI.h"

struct _ws_server_object {
    zend_object zo;
};

typedef struct _ws_server_object ws_server_object;

void ws_server_free_storage(void *object TSRMLS_DC);
zend_object_value ws_server_create_handler(zend_class_entry *type TSRMLS_DC);
int ws_server_object_count(zval *object, long *count TSRMLS_DC);
HashTable *ws_server_get_debug_info(zval *object, int *is_temp TSRMLS_DC);

extern zend_function_entry ws_server_methods[];
extern zend_object_handlers ws_server_object_handlers;

PHP_METHOD(WsServer, __construct);
PHP_METHOD(WsServer, receive);
PHP_METHOD(WsServer, processRawData);

PHP_METHOD(WsServer, serve);

PHP_METHOD(WsServer, callback);

PHP_METHOD(WsServer, onMessage);
PHP_METHOD(WsServer, setOnMessage);


#endif
