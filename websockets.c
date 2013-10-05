#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_websockets.h"

static zend_function_entry websockets_functions[] = {
    PHP_FE(is_ws, NULL)
    PHP_FE(ws_handshake, NULL)
    PHP_FE(ws_send, NULL)
    PHP_FE(ws_receive, NULL)
    PHP_FE(ws_close, NULL)
    {NULL, NULL, NULL}
}; 


PHP_MINIT_FUNCTION(websockets)
{
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

char* frame_concat(char* arr1, int len1, char* arr2, int len2) {
	char* total = malloc(len1 + len2); // array to hold the result

	memcpy(total,     arr1, len1);
	memcpy(total + len1, arr2, len2);
	
	return total;
}

char* encode_ws_frame(char* data, int opcode) {
	char* frame = malloc(2 * sizeof(char));	
	int frameLen = 0;	
	int i;

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
	
	frame[0] = b;
		
	int len = strlen(data);

	if(len <= 125) {
		b = (char) len; //set the message length
		b |= (0 << 7); //set off the mask

		frame[1] = b;
	}

	//append message	
	frame = frame_concat(frame, strlen(frame), data, strlen(data));
	
	return frame;
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

	
	/*
	* Since we are handling a WebSocket connection, not a standard HTTP
	* connection, remove the HTTP input filter.
	*/	
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
        //create the key
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

        RETURN_TRUE;
    }
	
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing 'Sec-WebSocket-Key' header. Can't handshake with the client.");


    RETURN_FALSE;
}

PHP_FUNCTION(ws_send) {
	char *str; 
	int str_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &str, &str_len) == FAILURE) {
		return;
	}

	char *frame = encode_ws_frame(str, 1); 

	//send data
	php_printf("%s", frame);
	sapi_flush(TSRMLS_C);

    RETURN_FALSE;
}

int parse_message(char *buffer, long blen) {
	long offset = 0;
	
	//read header
	if(WS_G(step) == 0) {
		WS_G(FIN) = (buffer[0] >> 7) & 1;
		WS_G(RSV1) = (buffer[0] >> 6) & 1;
		WS_G(RSV2) =(buffer[0] >> 5) & 1;
		WS_G(RSV3) =(buffer[0] >> 4) & 1;
		
		WS_G(opcode) = (buffer[0] & 0x0F);

		WS_G(haveMask) = (buffer[1] >> 7) & 1;
		WS_G(len) = buffer[1] & 0x7f;
		
		if(WS_G(len) <= 125) {
			WS_G(step) = 2;
		} else {
			WS_G(step) = 1;		
		}

		offset += 2;
	}

	//read length
	if(WS_G(step) == 1) {
		
		if (WS_G(len) == 126 && blen >= offset + 1) {
			WS_G(len) = buffer[offset] << 8 | buffer[offset + 1];
			offset += 2;
		} else if(blen < offset + 1){
			return 0;
		}

		if (WS_G(len) == 127 && blen >= offset + 8) {
			long l = ((long)buffer[offset]) << 56 | 
					 ((long)buffer[offset + 1]) << 48 | 
					 ((long)buffer[offset + 2]) << 40 | 
					 ((long)buffer[offset + 3]) << 32 | 
					 ((long)buffer[offset + 4]) << 24 | 
					 ((long)buffer[offset + 5]) << 16 | 
					 ((long)buffer[offset + 6]) << 8 | 
					 ((long)buffer[offset + 7]);
					 
			WS_G(len) = l;
			offset += 8;
		} else if(blen < offset + 8) {
			return 0;		
		}
	}

	//get the mask
	if(WS_G(step) == 2) {
		if(WS_G(haveMask)) {
			
		} else {
			WS_G(step) = 3;
		}
	}

	return 1;
}

PHP_FUNCTION(ws_receive) {
	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));
	
	apr_status_t rv;
    apr_bucket_brigade *bb;
	
	int reading = 1;

	char buffer[512];
	apr_size_t bufsiz = 512;

	sapi_flush(TSRMLS_C);
	apr_pool_t *pool = NULL;
    apr_bucket_alloc_t *bucket_alloc;

	if ((apr_pool_create(&pool, r->pool) == APR_SUCCESS) &&
        ((bucket_alloc = apr_bucket_alloc_create(pool)) != NULL) &&
        ((bb = apr_brigade_create(pool, bucket_alloc)) != NULL)) {	

		if((rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, bufsiz)) == APR_SUCCESS) {
			if ((rv = apr_brigade_flatten(bb, buffer, &bufsiz)) == APR_SUCCESS) {
				
				if(bufsiz > 0) {					
					parse_message(buffer, bufsiz);				
				}

				//WS_G(temp_buffer) = frame_concat(WS_G(temp_buffer), strlen(WS_G(temp_buffer)), buffer, strlen(buffer));
		    }
		}
	}
	
	char *key = emalloc(100);
    sprintf(key, "msg len %i \n", WS_G(len));
	
	php_error_docref(NULL TSRMLS_CC, E_WARNING, key);

    apr_brigade_destroy(bb);
}

PHP_FUNCTION(ws_close) {
	request_rec *r = (request_rec *)(((SG(server_context) == NULL) ? NULL : ((php_struct*)SG(server_context))->r));
	ap_lingering_close(r->connection);
}

