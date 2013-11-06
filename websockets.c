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

#include "php.h"
#include "php_websockets.h"

#define FRAME_SET_LENGTH(X64, IDX)  (unsigned char)(((X64) >> ((IDX)*8)) & 0xFF)

static zend_function_entry websockets_functions[] = {
    PHP_FE(is_ws, NULL)
    PHP_FE(ws_handshake, NULL)
    PHP_FE(ws_send, NULL)
    PHP_FE(ws_close, NULL)
    {NULL, NULL, NULL}
}; 


zend_object_handlers ws_frame_object_handlers;
zend_class_entry *ws_frame_ce;

zend_object_handlers ws_server_object_handlers;
zend_class_entry *ws_server_ce;

PHP_MINIT_FUNCTION(websockets)
{
	zend_class_entry ce;

	//initialize wsFrame class
	INIT_CLASS_ENTRY(ce, "WsFrame", ws_frame_methods);
	ws_frame_ce = zend_register_internal_class(&ce TSRMLS_CC);
	ws_frame_ce->create_object = ws_frame_create_handler;

	memcpy(&ws_frame_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	ws_frame_object_handlers.clone_obj = NULL;

	//payload
	zend_declare_property_long(ws_frame_ce, ZEND_STRS("currentLength")-1, -3, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(ws_frame_ce, ZEND_STRS("payloadLength")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(ws_frame_ce, ZEND_STRS("payloadData")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);

	//frame header
	zend_declare_property_bool(ws_frame_ce, ZEND_STRS("FIN")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_bool(ws_frame_ce, ZEND_STRS("RSV1")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_bool(ws_frame_ce, ZEND_STRS("RSV2")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_bool(ws_frame_ce, ZEND_STRS("RSV3")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(ws_frame_ce, ZEND_STRS("opcode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

	//masking data
	zend_declare_property_bool(ws_frame_ce, ZEND_STRS("haveMask")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(ws_frame_ce, ZEND_STRS("mask")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);


	//initialize wsServer class
	INIT_CLASS_ENTRY(ce, "WsServer", ws_server_methods);
	ws_server_ce = zend_register_internal_class(&ce TSRMLS_CC);
	ws_server_ce->create_object = ws_server_create_handler;

	memcpy(&ws_server_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	ws_server_object_handlers.clone_obj = NULL;

	//init frame property
	zend_declare_property_bool(ws_server_ce, ZEND_STRS("readInBlockingMode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

	zend_declare_property_long(ws_server_ce, ZEND_STRS("readInterval") - 1, 1000, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_bool(ws_server_ce, ZEND_STRS("serving") - 1, 1, ZEND_ACC_PUBLIC TSRMLS_CC);

	zend_declare_property_null(ws_server_ce, ZEND_STRS("readFrame") - 1, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(ws_server_ce, ZEND_STRS("readBuffer") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);

	zend_declare_property_null(ws_server_ce, ZEND_STRS("_onMessage") - 1, ZEND_ACC_PROTECTED TSRMLS_CC);
	zend_declare_property_null(ws_server_ce, ZEND_STRS("_beforeRead") - 1, ZEND_ACC_PROTECTED TSRMLS_CC);
	zend_declare_property_null(ws_server_ce, ZEND_STRS("_afterRead") - 1, ZEND_ACC_PROTECTED TSRMLS_CC);
	zend_declare_property_null(ws_server_ce, ZEND_STRS("_beforeProcess") - 1, ZEND_ACC_PROTECTED TSRMLS_CC);
	zend_declare_property_null(ws_server_ce, ZEND_STRS("_afterProcess") - 1, ZEND_ACC_PROTECTED TSRMLS_CC);

	return SUCCESS;
}

PHP_RINIT_FUNCTION(websockets_request) {

	return SUCCESS;
}

zend_module_entry websockets_module_entry = {
    #if ZEND_MODULE_API_NO >= 20010901
        STANDARD_MODULE_HEADER,
    #endif
   
    PHP_WEBSOCKETS_EXTNAME,
    websockets_functions,  /* Functions */
    PHP_MINIT(websockets), /* MODULE INIT */
    NULL,                  /* MSHUTDOWN */
    PHP_RINIT(websockets_request),  /* RINIT */
    NULL,                  /* RSHUTDOWN */
    NULL,                  /* MINFO */

    #if ZEND_MODULE_API_NO >= 20010901
        PHP_WEBSOCKETS_VERSION,
    #endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_WEBSOCKETS

ZEND_GET_MODULE(websockets)

#endif

ZEND_DECLARE_MODULE_GLOBALS(websockets);



char* getHeader(char* key) {
    zval **server_vars;
    zval **var;

    zend_is_auto_global("_SERVER", sizeof("_SERVER")-1 TSRMLS_CC);

    if (zend_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER"), (void **) &server_vars) == SUCCESS && Z_TYPE_PP(server_vars) == IS_ARRAY  && //check for _SERVER variable
        zend_hash_find(Z_ARRVAL_PP(server_vars), key, strlen(key)+1, (void **) &var)==SUCCESS && Z_TYPE_PP(var) == IS_STRING ) {

        return Z_STRVAL_PP(var);
    }

    return NULL;
}

char* getSec(char* key) {
	
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, key, strlen(key));	
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1_Final(hash, &ctx);
	
	int str_len = 20;
	int ret_length;

	return php_base64_encode((unsigned char*)hash, SHA_DIGEST_LENGTH, &ret_length);
}

char* frame_concat(char* arr1, long len1, char* arr2, long len2) {
	char* total = emalloc(len1 + len2); // array to hold the result

	memcpy(total, arr1, len1);
	memcpy(total + len1, arr2, len2);
	
	return total;
}

/**
 * Check if the current request is a websocket request or not
 * 
 * @return bool
 */
PHP_FUNCTION(is_ws)
{
    char *version = getHeader("HTTP_SEC_WEBSOCKET_VERSION");
    char *upgrade = getHeader("HTTP_UPGRADE");
    char *key = getHeader("HTTP_SEC_WEBSOCKET_KEY");

    if(version == NULL || strcmp(version, "13") != 0) {
        RETURN_FALSE;
    }

    if(upgrade == NULL || strcmp(upgrade, "websocket") != 0) {
        RETURN_FALSE;
    }

    if(key == NULL) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}


PHP_FUNCTION(ws_handshake) {

	//Since we are handling a WebSocket connection, not a standard HTTP
	//connection, remove the HTTP input filter.

	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));

	ap_filter_t *input_filter;

	for (input_filter = r->input_filters;
		input_filter != NULL;
		input_filter = input_filter->next) {
			if ((input_filter->frec != NULL) &&
			(input_filter->frec->name != NULL) &&
			!strcasecmp(input_filter->frec->name, "http_in")) {
				ap_remove_input_filter(input_filter);
				break;
			}
	}
	
	apr_table_clear(r->headers_out);
	//apr_socket_timeout_set(ap_get_module_config(r->connection->conn_config, &core_module), -1);

    //set the status
	int responseNo = 101;
    sapi_header_op(SAPI_HEADER_SET_STATUS, 101 TSRMLS_CC);
    
    //websocket headers
    sapi_header_line ctr = {0};
    ctr.line = "Upgrade: websocket";
    ctr.line_len = strlen(ctr.line);
    sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC);

    ctr.line = "Content-length: 0";
    ctr.line_len = strlen(ctr.line);
    sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC);

	ctr.line = "Connection: Upgrade";
    ctr.line_len = strlen(ctr.line);
    sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC);

    char *clientKey = getHeader("HTTP_SEC_WEBSOCKET_KEY"); 

    if(clientKey != NULL) {
        //crea 	te the key
        char *key = emalloc(100);
        sprintf(key, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", clientKey);

        //hash the key
        char *target = getSec(key);
       
        //create header
        char *sec = emalloc((size_t) (strlen("Sec-WebSocket-Accept: ") + 100) );
        sprintf(sec, "Sec-WebSocket-Accept: %s", target);
        
        //send the header
        sapi_header_line ctr = {0};
        ctr.line = sec;
        ctr.line_len = strlen(sec);
        sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC); 
        
        efree(sec);
        sapi_flush(TSRMLS_C);
		
		WS_G(step) = 0;

		apr_pool_create(&WS_G(pool), r->pool);
        WS_G(bucket_alloc) = apr_bucket_alloc_create(WS_G(pool));
		WS_G(obb) = apr_brigade_create(WS_G(pool), WS_G(bucket_alloc));

		ap_filter_t *out_filter;
	
		for (out_filter = r->output_filters;
			out_filter != NULL;
			out_filter = out_filter->next) {
				if ((out_filter->frec != NULL) &&
				(out_filter->frec->name != NULL) &&
				strcasecmp(out_filter->frec->name, "core")) {
					ap_remove_output_filter(out_filter);
				}

				if ((out_filter->frec != NULL) &&
				(out_filter->frec->name != NULL) &&
				!strcasecmp(out_filter->frec->name, "old_write")) {
					ap_remove_output_filter(out_filter);
				}
		}

		RETURN_TRUE;
    }

	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing 'Sec-WebSocket-Key' header. Can't handshake with the client.");

    RETURN_FALSE;
}


void ws_send_message(char* str, long len, int opcode) {
	char *frame;

	int frameLen = 0;
	if(len < 0) {
		len = strlen(str);	
	}

	int FIN = 1;
	int RSV1 = 0;
	int RSV2 = 0;
	int RSV3 = 0;

	char b = opcode;
	b |= FIN << 7;
	b |= RSV1 << 6;
	b |= RSV2 << 5;
	b |= RSV3 << 4;
	b |= ((opcode) & 0x0F);
	
	if(len <= 125) {
		frame = emalloc(2);
		frameLen = 2;
		frame[0] = b;

		b = (char) len; //set the message length
		b |= (0 << 7); //set off the mask

		frame[1] = b;	
	} else if (len <= 255 * 255 - 1) {
		frame = emalloc(4);	
		frameLen = 4;
		frame[0] = b;

		b = 126;
		b |= (0 << 7);
		frame[1] = b;
		frame[2] = FRAME_SET_LENGTH(len, 1);
        frame[3] = FRAME_SET_LENGTH(len, 0);
	} else {
		frame = emalloc(10);
		frameLen = 10;
		frame[0] = b;

		b = 127;
		b |= (0 << 7);
		frame[1] = b;
		frame[2] = FRAME_SET_LENGTH(len, 7);
		frame[3] = FRAME_SET_LENGTH(len, 6);
		frame[4] = FRAME_SET_LENGTH(len, 5);
		frame[5] = FRAME_SET_LENGTH(len, 4);
		frame[6] = FRAME_SET_LENGTH(len, 3);
		frame[7] = FRAME_SET_LENGTH(len, 2);
		frame[8] = FRAME_SET_LENGTH(len, 1);
        frame[9] = FRAME_SET_LENGTH(len, 0);
	}

	PHPWRITE(frame, frameLen);
	sapi_flush(TSRMLS_C);

	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));

	ap_filter_t *of = r->connection->output_filters;

	ap_fwrite(of, WS_G(obb), str, strlen(str));
   	ap_fflush(of, WS_G(obb));

}

PHP_FUNCTION(ws_send) {

	zval *msg;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &msg) == FAILURE) {
		return;
	}

    //send message as string
    if(Z_TYPE_P(msg) == IS_STRING) {
		ws_send_message(Z_STRVAL_P(msg), Z_STRLEN_P(msg), 1);
		RETURN_TRUE;
	}

    //encode object and send it
    if(Z_TYPE_P(msg) == IS_OBJECT) {
    	zval *retval_ptr;
    	zend_call_method( &msg, Z_OBJCE_P(msg), NULL, "encode", sizeof("encode")-1,  &retval_ptr, 0, NULL, NULL TSRMLS_CC );

    	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));

		ap_filter_t *of = r->connection->output_filters;

		ap_fwrite(of, WS_G(obb), Z_STRVAL_P(retval_ptr), Z_STRLEN_P(retval_ptr));
		ap_fflush(of, WS_G(obb));

    	RETURN_TRUE;
	}

    RETURN_FALSE;
}

PHP_FUNCTION(ws_close) {
	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));
	ap_lingering_close(r->connection);
}

