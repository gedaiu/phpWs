#ifndef PHP_HTTP_WSFRAME_H
#define PHP_HTTP_WSFRAME_H

#include "php.h"
#include "php_main.h"

struct _ws_frame_object {
    zend_object zo;
};

typedef struct _ws_frame_object ws_frame_object;

void ws_frame_free_storage(void *object TSRMLS_DC);
zend_object_value ws_frame_create_handler(zend_class_entry *type TSRMLS_DC);
int ws_frame_object_count(zval *object, long *count TSRMLS_DC);
HashTable *ws_frame_get_debug_info(zval *object, int *is_temp TSRMLS_DC);

extern zend_function_entry ws_frame_methods[];
extern zend_object_handlers ws_frame_object_handlers;

PHP_METHOD(WsFrame, __construct);
PHP_METHOD(WsFrame, __toString);
PHP_METHOD(WsFrame, push);
PHP_METHOD(WsFrame, encode);
PHP_METHOD(WsFrame, isReady);
PHP_METHOD(WsFrame, reset);

#endif
