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

#include "wsServer.h"

extern zend_object_handlers ws_server_object_handlers;
extern zend_class_entry *ws_server_ce;

extern zend_object_handlers ws_frame_object_handlers;
extern zend_class_entry *ws_frame_ce;

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server_receive, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server_processRawData, 0, 0, 1)
	ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server_serve, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server_callback, 0, 0, 1)
	ZEND_ARG_INFO(0, function)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server_onMessage, 0, 0, 1)
	ZEND_ARG_INFO(0, WsFrame)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_server_setOnMessage, 0, 0, 1)
	ZEND_ARG_INFO(0, function)
ZEND_END_ARG_INFO()


/**
 * Delete CmsValue object
 */
void ws_server_free_storage(void *object TSRMLS_DC) {
	ws_server_object *obj = (ws_server_object *)object;
    efree(obj);
}

/**
 * Create CmsValueObject
 */
zend_object_value ws_server_create_handler(zend_class_entry *ce TSRMLS_DC) {

	zend_object_value retval;
	ws_server_object* intern;

	intern = (ws_server_object*)ecalloc(1, sizeof(ws_server_object));

	zend_object_std_init(&intern->zo, ce TSRMLS_CC);

	#if PHP_VERSION_ID < 50399
		zend_hash_copy(intern->zo.properties, &(ce->default_properties), (copy_ctor_func_t) zval_add_ref, NULL, sizeof(zval*));
	#else
		object_properties_init((zend_object*) intern, ce);
	#endif


	retval.handle = zend_objects_store_put(
			intern,
			(zend_objects_store_dtor_t) zend_objects_destroy_object,
			(zend_objects_free_object_storage_t) ws_server_free_storage,
			NULL TSRMLS_CC);

	retval.handlers = &ws_server_object_handlers;

	return retval;
}

zend_function_entry ws_server_methods[] = {
	PHP_ME(WsServer,  __construct, arginfo_ws_server___construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)

	PHP_ME(WsServer, receive, arginfo_ws_server_receive, ZEND_ACC_PUBLIC)
	PHP_ME(WsServer, processRawData, arginfo_ws_server_processRawData, ZEND_ACC_PUBLIC)
	PHP_ME(WsServer, serve, arginfo_ws_server_serve, ZEND_ACC_PUBLIC)

	PHP_ME(WsServer, callback, arginfo_ws_server_callback, ZEND_ACC_PRIVATE)

	PHP_ME(WsServer, onMessage, arginfo_ws_server_onMessage, ZEND_ACC_PUBLIC)
	PHP_ME(WsServer, setOnMessage, arginfo_ws_server_onMessage, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};


PHP_METHOD(WsServer, __construct) {
	//create the reading WsFrame object
	zval *zobj_wsFrame;
	MAKE_STD_ZVAL(zobj_wsFrame);
	Z_TYPE_P(zobj_wsFrame) = IS_OBJECT;
	object_init_ex(zobj_wsFrame, ws_frame_ce);

	zend_update_property(ws_server_ce, getThis(), ZEND_STRS("readFrame")-1, zobj_wsFrame TSRMLS_CC);
}

PHP_METHOD(WsServer, receive) {

	//TODO: CALL ON BEFORE READ

	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));

	apr_status_t rv;
	apr_bucket_brigade *bb;
    apr_bucket_alloc_t *bucket_alloc;
	apr_pool_t *pool;

	char *buffer = emalloc(2048);
	apr_size_t bufsiz = 2048;

	apr_pool_create(&pool, r->pool);
	bucket_alloc = apr_bucket_alloc_create(pool);
	bb = apr_brigade_create(pool, bucket_alloc);

	ZVAL_EMPTY_STRING(return_value);

	zval *zReadInBlockingMode = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readInBlockingMode")-1, 0 TSRMLS_CC);

	if(Z_BVAL_P(zReadInBlockingMode)) {
		rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, bufsiz);
	} else {
		rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_NONBLOCK_READ, bufsiz);
	}

	if(rv == APR_SUCCESS) {
		if ((rv = apr_brigade_flatten(bb, buffer, &bufsiz)) == APR_SUCCESS) {
			if(bufsiz > 0) {
				ZVAL_STRINGL(return_value, buffer, bufsiz, 1);
			}
		}
	}
	
	apr_brigade_destroy(bb);
	apr_bucket_alloc_destroy(bucket_alloc);
	apr_pool_destroy(pool);

	//TODO: CALL ON AFTER READ
}

PHP_METHOD(WsServer, processRawData) {
	zval *zBuffer;

	//get parameters
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zBuffer)) {
		return;
	}

	zval *data = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readBuffer")-1, 0 TSRMLS_CC);

	if(Z_STRLEN_P(data) == 0) {
	} else {
		ZVAL_STRINGL(data, strcat(Z_STRVAL_P(data), Z_STRVAL_P(zBuffer)), Z_STRLEN_P(data) + Z_STRLEN_P(zBuffer), 1);
	}

	zend_update_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readBuffer")-1, data TSRMLS_CC);

	//TODO: CALL ON BEFORE PROCESS

	//push data into frame
	zval *readFrame = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readFrame")-1, 0 TSRMLS_CC);

	zval *retval_ptr;
	zend_call_method( &readFrame, Z_OBJCE_P(readFrame), NULL, "push",  strlen("push"),  &retval_ptr, 1, data, NULL TSRMLS_CC );
	long readBytes = Z_LVAL_P(retval_ptr);

	if(readBytes == -1) {
		zend_update_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("serving")-1, 0 TSRMLS_CC);
	}

	if(readBytes > 0) {
		char *buffer = Z_STRVAL_P(data);
		long buffer_len = (long)Z_STRLEN_P(data);

		//remove data from buffer
		if(readBytes < buffer_len) {
			buffer_len -= readBytes;
			memmove(buffer, buffer + readBytes, data->value.str.len);
			data->value.str.val = erealloc(data->value.str.val, data->value.str.len);

			ZVAL_STRINGL(data, buffer, buffer_len, 0);
		} else {
			ZVAL_EMPTY_STRING(data);
		}

		zend_update_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readBuffer")-1, data TSRMLS_CC);
	}

	zval *currentLength = zend_read_property(Z_OBJCE_P(readFrame), readFrame, ZEND_STRS("currentLength")-1, 0 TSRMLS_CC);
	zval *payloadLength = zend_read_property(Z_OBJCE_P(readFrame), readFrame, ZEND_STRS("payloadLength")-1, 0 TSRMLS_CC);

	if(Z_LVAL_P(currentLength) == Z_LVAL_P(payloadLength)) {
		zend_call_method( &getThis(), Z_OBJCE_P(getThis()), NULL, "onmessage", sizeof("onmessage")-1,  NULL, 1, readFrame, NULL TSRMLS_CC );
		zend_call_method( &readFrame, Z_OBJCE_P(readFrame), NULL, "reset",  strlen("reset"),  NULL, 0, NULL, NULL TSRMLS_CC );
	}

	//TODO: CALL ON AFTER PROCESS
	
	RETURN_TRUE;
}


PHP_METHOD(WsServer, onMessage) {
	zval *zFrame;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zFrame) == FAILURE) {
		return;
	}

	zval *z_onMessage = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("_onMessage")-1, 0 TSRMLS_CC);
	zval *zReadFrame = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readFrame")-1, 0 TSRMLS_CC);

	zend_fcall_info *fci;
	zend_fcall_info_cache *fcc;
	char *is_callable_error = NULL;

	if (Z_TYPE_P(z_onMessage) == IS_NULL) {
		return;
	}

	zend_call_method( &getThis(), Z_OBJCE_P(getThis()), NULL, "callback", sizeof("callback")-1,  NULL, 2, z_onMessage, zReadFrame TSRMLS_CC );
}

PHP_METHOD(WsServer, setOnMessage) {

	zval *zCall;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zCall)) {
		return;
	}

	zend_update_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("_onMessage")-1, zCall TSRMLS_CC);
}

PHP_METHOD(WsServer, callback) {
	zval *params, *retval_ptr = NULL;
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "f*", &fci, &fci_cache, &fci.params, &fci.param_count) == FAILURE) {
		return;
	}

	fci.retval_ptr_ptr = &retval_ptr;

	if (zend_call_function(&fci, &fci_cache TSRMLS_CC) == SUCCESS && fci.retval_ptr_ptr && *fci.retval_ptr_ptr) {
		COPY_PZVAL_TO_ZVAL(*return_value, *fci.retval_ptr_ptr);
	}

	zend_fcall_info_args_clear(&fci, 1);
}

PHP_METHOD(WsServer, serve) {
	//zend_update_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("serving")-1, 1 TSRMLS_CC);

	int serving = 1;

	while(serving) {
		zval *retval_ptr;
		zend_call_method( &getThis(), Z_OBJCE_P(getThis()), NULL, "receive", sizeof("receive")-1, &retval_ptr, 0, NULL, NULL TSRMLS_CC );

		zend_call_method( &getThis(), Z_OBJCE_P(getThis()), NULL, "processrawdata", sizeof("processrawdata")-1,  NULL, 1, retval_ptr, NULL TSRMLS_CC );

		zval *zReadInBlockingMode = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readInBlockingMode")-1, 0 TSRMLS_CC);
		zval *zReadInterval = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("readInterval")-1, 0 TSRMLS_CC);
		zval *zServing = zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRS("serving")-1, 0 TSRMLS_CC);

		serving = Z_BVAL_P(zServing);

		if(!Z_BVAL_P(zReadInBlockingMode)) {
			usleep(Z_LVAL_P(zReadInterval));
		}
	}
}

