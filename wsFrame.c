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

extern zend_object_handlers ws_frame_object_handlers;
extern zend_class_entry *ws_frame_ce;

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame___toString, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame_encode, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame_push, 0, 0, 1)
	ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame_is_ready, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ws_frame_reset, 0, 0, 0)
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
	PHP_ME(WsFrame, encode, arginfo_ws_frame_push, ZEND_ACC_PUBLIC)
	PHP_ME(WsFrame, isReady, arginfo_ws_frame_is_ready, ZEND_ACC_PUBLIC)
	PHP_ME(WsFrame, reset, arginfo_ws_frame_is_ready, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};


PHP_METHOD(WsFrame, __construct) {

}

PHP_METHOD(WsFrame, __toString) {
	RETURN_STRING( "test",  4);
}

PHP_METHOD(WsFrame, push) {
	char *buffer;
	int buffer_len;

	//get parameters
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &buffer, &buffer_len)) {
		return;
	}

	//get object properties
	long currentLength = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("currentLength")-1, 0 TSRMLS_CC));
	long payloadLength = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("payloadLength")-1, 0 TSRMLS_CC));
	char *payloadData = Z_STRVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("payloadData")-1, 0 TSRMLS_CC));

	int FIN = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("FIN")-1, 0 TSRMLS_CC));
	int RSV1 = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("RSV1")-1, 0 TSRMLS_CC));
	int RSV2 = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("RSV2")-1, 0 TSRMLS_CC));
	int RSV3 = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("RSV3")-1, 0 TSRMLS_CC));


	int opcode = Z_LVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("opcode")-1, 0 TSRMLS_CC));

	int haveMask = Z_BVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("haveMask")-1, 0 TSRMLS_CC));
	char *mask = Z_STRVAL_P(zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("mask")-1, 0 TSRMLS_CC));

	//
	long written = 0;
	long offset = 0;

	//get the frame info
	if(currentLength == -3 && buffer_len >= 2) {
		FIN  = (buffer[0] >> 7) & 1;
		RSV1 = (buffer[0] >> 6) & 1;
		RSV2 = (buffer[0] >> 5) & 1;
		RSV3 = (buffer[0] >> 4) & 1;

		opcode = (buffer[0] & 0x0F);

		haveMask = (buffer[1] >> 7) & 1;
		payloadLength = buffer[1] & 0x7f;

		if(opcode <= 10) {
			currentLength = -2;
			offset += 2;
		} else {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid opcode `%i`", opcode);
			RETURN_LONG(-1);
		}
	}

	//get the payload length
	if(currentLength == -2) {

		if(payloadLength < 126) {
			currentLength = -1;
		}

		if (payloadLength == 126 && offset + 2 < buffer_len) {
			payloadLength = 0;
			payloadLength = ((unsigned char)buffer[offset] << 8) + (unsigned char)buffer[offset + 1];

			offset += 2;
			currentLength = -1;
		}

		if (payloadLength == 127 && offset + 8 < buffer_len) {

			long l = (long)((unsigned char)buffer[offset]) << 56 |
					 (long)((unsigned char)buffer[offset + 1]) << 48 |
					 (long)((unsigned char)buffer[offset + 2]) << 40 |
					 (long)((unsigned char)buffer[offset + 3]) << 32 |
					 (long)((unsigned char)buffer[offset + 4]) << 24 |
					 (long)((unsigned char)buffer[offset + 5]) << 16 |
					 (long)((unsigned char)buffer[offset + 6]) << 8 |
					 (long)((unsigned char)buffer[offset + 7]);

			payloadLength = l;

			offset += 8;
			currentLength = -1;
		}
	}

	//get the mask
	if(currentLength == -1 && offset + 4 < buffer_len ) {
		if(haveMask) {
			memcpy(mask, buffer + offset, 4);
			offset += 4;
		}

		currentLength = 0;
	}

	//push data into payload
	if(currentLength >= 0) {
		long need = payloadLength - currentLength;

		if(need > buffer_len - offset) {
			payloadData = strcat(payloadData, buffer + offset);
			currentLength += buffer_len - offset;

			written = buffer_len;
		} else {
			char *tmp = emalloc(need);
			memcpy(tmp, buffer + offset, need);
			payloadData = strcat(payloadData, tmp);

			efree(tmp);
			currentLength = payloadLength;

			written = need;
		}
	}

	//update the object properties
	zval *zCurrentLength;
	MAKE_STD_ZVAL(zCurrentLength);
	Z_TYPE_P(zCurrentLength) = IS_LONG;
	Z_LVAL_P(zCurrentLength) = currentLength;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("currentLength")-1, zCurrentLength TSRMLS_CC);
	zval_ptr_dtor(&zCurrentLength);

	zval *zPayloadLength;
	MAKE_STD_ZVAL(zPayloadLength);
	Z_TYPE_P(zPayloadLength) = IS_LONG;
	Z_LVAL_P(zPayloadLength) = payloadLength;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("payloadLength")-1, zPayloadLength TSRMLS_CC);
	zval_ptr_dtor(&zPayloadLength);

	if(currentLength >= 0) {
		zval *zPayloadData;
		MAKE_STD_ZVAL(zPayloadData);
		Z_TYPE_P(zPayloadData) = IS_STRING;
		Z_STRVAL_P(zPayloadData) = payloadData;
		Z_STRLEN_P(zPayloadData) = currentLength;
		zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("payloadData")-1, zPayloadData TSRMLS_CC);
		zval_ptr_dtor(&zPayloadData);
	}

	zval *zFIN;
	MAKE_STD_ZVAL(zFIN);
	Z_TYPE_P(zFIN) = IS_BOOL;
	Z_LVAL_P(zFIN) = FIN;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("FIN")-1, zFIN TSRMLS_CC);
	zval_ptr_dtor(&zFIN);

	zval *zRSV1;
	MAKE_STD_ZVAL(zRSV1);
	Z_TYPE_P(zRSV1) = IS_LONG;
	Z_LVAL_P(zRSV1) = RSV1;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("RSV1")-1, zRSV1 TSRMLS_CC);
	zval_ptr_dtor(&zRSV1);

	zval *zRSV2;
	MAKE_STD_ZVAL(zRSV2);
	Z_TYPE_P(zRSV2) = IS_LONG;
	Z_LVAL_P(zRSV2) = RSV1;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("RSV2")-1, zRSV2 TSRMLS_CC);
	zval_ptr_dtor(&zRSV2);

	zval *zRSV3;
	MAKE_STD_ZVAL(zRSV3);
	Z_TYPE_P(zRSV3) = IS_LONG;
	Z_LVAL_P(zRSV3) = RSV1;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("RSV3")-1, zRSV3 TSRMLS_CC);
	zval_ptr_dtor(&zRSV3);

	zval *zOpcode;
	MAKE_STD_ZVAL(zOpcode);
	Z_TYPE_P(zOpcode) = IS_LONG;
	Z_LVAL_P(zOpcode) = opcode;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("opcode")-1, zOpcode TSRMLS_CC);
	zval_ptr_dtor(&zOpcode);

	zval *zHaveMask;
	MAKE_STD_ZVAL(zHaveMask);
	Z_TYPE_P(zHaveMask) = IS_BOOL;
	Z_LVAL_P(zHaveMask) = haveMask;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("haveMask")-1, zHaveMask TSRMLS_CC);
	zval_ptr_dtor(&zHaveMask);

	zval *zMask;
	MAKE_STD_ZVAL(zMask);
	Z_TYPE_P(zMask) = IS_STRING;

	if(haveMask) {
		Z_STRVAL_P(zMask) = mask;
		Z_STRLEN_P(zMask) = 4;
	} else {
		Z_STRVAL_P(zMask) = "";
		Z_STRLEN_P(zMask) = 0;
	}

	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("mask")-1, zMask TSRMLS_CC);
	zval_ptr_dtor(&zMask);

	RETURN_LONG(written);
}

PHP_METHOD(WsFrame, encode) {

}

PHP_METHOD(WsFrame, isReady) {
	zval *currentLength = zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("currentLength")-1, 0 TSRMLS_CC);
	zval *payloadLength = zend_read_property(ws_frame_ce, getThis(), ZEND_STRS("payloadLength")-1, 0 TSRMLS_CC);

	if(Z_LVAL_P(currentLength) == Z_LVAL_P(payloadLength)) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}

PHP_METHOD(WsFrame, reset) {
	//reset the object properties
	zval *zCurrentLength;
	MAKE_STD_ZVAL(zCurrentLength);
	Z_TYPE_P(zCurrentLength) = IS_LONG;
	Z_LVAL_P(zCurrentLength) = -3;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("currentLength")-1, zCurrentLength TSRMLS_CC);
	zval_ptr_dtor(&zCurrentLength);

	zval *zPayloadLength;
	MAKE_STD_ZVAL(zPayloadLength);
	Z_TYPE_P(zPayloadLength) = IS_LONG;
	Z_LVAL_P(zPayloadLength) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("payloadLength")-1, zPayloadLength TSRMLS_CC);
	zval_ptr_dtor(&zPayloadLength);

	zval *zPayloadData;
	MAKE_STD_ZVAL(zPayloadData);
	Z_TYPE_P(zPayloadData) = IS_STRING;
	Z_STRVAL_P(zPayloadData) = "";
	Z_STRLEN_P(zPayloadData) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("payloadData")-1, zPayloadData TSRMLS_CC);
	zval_ptr_dtor(&zPayloadData);

	zval *zFIN;
	MAKE_STD_ZVAL(zFIN);
	Z_TYPE_P(zFIN) = IS_BOOL;
	Z_LVAL_P(zFIN) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("FIN")-1, zFIN TSRMLS_CC);
	zval_ptr_dtor(&zFIN);

	zval *zRSV1;
	MAKE_STD_ZVAL(zRSV1);
	Z_TYPE_P(zRSV1) = IS_LONG;
	Z_LVAL_P(zRSV1) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("RSV1")-1, zRSV1 TSRMLS_CC);
	zval_ptr_dtor(&zRSV1);

	zval *zRSV2;
	MAKE_STD_ZVAL(zRSV2);
	Z_TYPE_P(zRSV2) = IS_LONG;
	Z_LVAL_P(zRSV2) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("RSV2")-1, zRSV2 TSRMLS_CC);
	zval_ptr_dtor(&zRSV2);

	zval *zRSV3;
	MAKE_STD_ZVAL(zRSV3);
	Z_TYPE_P(zRSV3) = IS_LONG;
	Z_LVAL_P(zRSV3) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("RSV3")-1, zRSV3 TSRMLS_CC);
	zval_ptr_dtor(&zRSV3);

	zval *zOpcode;
	MAKE_STD_ZVAL(zOpcode);
	Z_TYPE_P(zOpcode) = IS_LONG;
	Z_LVAL_P(zOpcode) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("opcode")-1, zOpcode TSRMLS_CC);
	zval_ptr_dtor(&zOpcode);

	zval *zHaveMask;
	MAKE_STD_ZVAL(zHaveMask);
	Z_TYPE_P(zHaveMask) = IS_BOOL;
	Z_LVAL_P(zHaveMask) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("haveMask")-1, zHaveMask TSRMLS_CC);
	zval_ptr_dtor(&zHaveMask);

	zval *zMask;
	MAKE_STD_ZVAL(zMask);
	Z_TYPE_P(zMask) = IS_STRING;
	Z_STRVAL_P(zMask) = "";
	Z_STRLEN_P(zMask) = 0;
	zend_update_property(ws_frame_ce, getThis(), ZEND_STRS("mask")-1, zMask TSRMLS_CC);
	zval_ptr_dtor(&zMask);
}
