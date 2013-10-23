/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2008 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Szabo Bogdan <szabobogdan@yahoo.com>                        |
  +----------------------------------------------------------------------+
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "wsFrame.h"


ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame___toString, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame_push, 0, 0, 1)
	ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

/**
 * Delete CmsValue object
 */
void ws_frame_free_storage(void *object TSRMLS_DC) {
	//ws_frame_object *obj = (ws_frame_object *)object;
    //efree(obj);
}

/**
 * Create CmsValueObject
 */
zend_object_value ws_frame_create_handler(zend_class_entry *ce TSRMLS_DC) {

	zend_object_value       retval;
	ws_frame_object*   intern;

	intern = (ws_frame_object*)ecalloc(1, sizeof(ws_frame_object));

	zend_object_std_init(&intern->zo, ce TSRMLS_CC);

	#if PHP_VERSION_ID < 50399
		zend_hash_copy(intern->zo.properties, &(ce->default_properties), (copy_ctor_func_t) zval_add_ref, NULL, sizeof(zval*));
	#else
		object_properties_init((zend_object*) intern, ce);
	#endif


	retval.handle = zend_objects_store_put(
			intern,
			(zend_objects_store_dtor_t) zend_objects_destroy_object,
			(zend_objects_free_object_storage_t) ws_frame_free_storage,
			NULL TSRMLS_CC);

	retval.handlers = &ws_frame_object_handlers;

	return retval;
}

zend_function_entry ws_frame_methods[] = {
	PHP_ME(WsFrame,  __construct, arginfo_ws_frame___construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)

	PHP_ME(WsFrame, __toString, arginfo_ws_frame___toString, ZEND_ACC_PUBLIC)
	PHP_ME(WsFrame, push, arginfo_ws_frame_push, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};


PHP_METHOD(WsFrame, __construct) {

}

PHP_METHOD(WsFrame, __toString) {
	RETURN_STRING( "test",  4);
}

PHP_METHOD(WsFrame, push) {

}
